# Backstage / Background Access — Design

Backstage lets a technician work on a remote machine **without disturbing the logged-in
user** — no taking over their screen, no watching the mouse move by itself. It's one of
ScreenConnect's most distinctive features and the most technically demanding one in this
project. This document is grounded in deep research into the Windows internals and how the
whole market actually implements it.

---

## The single most important finding

**"Backstage" in the market means two architecturally different things, and most tools
ship only the first:**

1. **Headless tool panels** — processes, services, registry, files, event log, and a
   terminal are queried over a structured channel and **rendered in the technician's own
   web UI**. No remote GUI, no hidden desktop. This is what SimpleHelp, Splashtop, GoTo/
   LogMeIn Resolve, TeamViewer Remote Management, Dameware, N-able Take Control, Atera,
   Action1, and Kaseya/Datto all actually do.

2. **A hidden interactive GUI desktop** — a real, invisible Windows desktop where arbitrary
   GUI apps run unseen by the user, composited back to the technician. **This is
   ScreenConnect Backstage's true differentiator and it is nearly unique in the legitimate
   market.** NinjaOne's "Background Mode" is the only close commercial analog (separate
   SYSTEM desktop, but a curated tool set, not arbitrary apps). The only other place this
   exact technique exists is **HVNC (Hidden VNC) malware** — the mechanism is
   indistinguishable, which is why AV/EDR vendors, including Microsoft Defender, actively
   detect "suspicious processes running on hidden desktops."

**Strategic recommendation: build #1 as the primary product, and treat #2 as an optional,
carefully-scoped, later addition.** The headless panels cover the large majority of real
backstage use cases, are lower-bandwidth, feel faster (native UI, not remoted pixels),
work regardless of GPU/app type, don't trip HVNC heuristics nearly as hard, and are far
less risky to build. The hidden GUI desktop is genuinely valuable for the cases a panel
can't express (a GUI-only installer, a vendor config tool), but it is complex, scope-
limited, and AV-sensitive. Leading with panels is both better product and better
engineering sequencing.

---

## Part 1 — Headless tool channels (the primary backstage)

Structured `Request → typed Response` RPC over the existing session, rendered natively in
the technician's browser UI. The agent is Rust running as a LocalSystem service. Build each
as its own channel; do the blocking Win32 work off the async runtime (`spawn_blocking`).

### Interactive shell — the one that feels most like magic

Use **ConPTY** (the Windows pseudoconsole API: `CreatePseudoConsole`,
`ResizePseudoConsole`, `ClosePseudoConsole`, wired via `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`
on `STARTUPINFOEX`). The agent is a **dumb byte relay**: ConPTY already emits and consumes
VT/ANSI, so you pass its output straight to **xterm.js** in the browser and pipe xterm.js
keystrokes straight back — no ANSI parsing on the agent. Resize on xterm's `onResize`; send
bytes as **binary** WebSocket frames (ConPTY output can split UTF-8 across reads — let
xterm.js reassemble). Implement flow control (pause reading the pipe when the browser's
buffer backs up) so `dir /s` doesn't blow up memory.

Requires Windows 10 1809+ (build 17763), which is every supported Windows. Rust: start with
`portable-pty` or `conpty`, but you'll likely outgrow them and hand-roll the
`STARTUPINFOEX` + attribute list with the `windows` crate, because you need
`CreateProcessAsUser` (not `CreateProcessW`) to run the shell under a chosen token — see
privilege model below.

### The rest of the panels

| Panel | Core Win32 API | Notes |
|---|---|---|
| **File manager** | `FindFirstFileExW` (`FindExInfoBasic` + `LARGE_FETCH`) | Long paths via `\\?\` prefix; detect `FILE_ATTRIBUTE_REPARSE_POINT` and don't follow junctions in recursive walks; surface per-entry access-denied as a padlock, don't abort the listing; network shares need an impersonated user token (SYSTEM has no network identity). |
| **File transfer** | chunked `begin/chunk/commit` | Per-chunk CRC32 + whole-file SHA-256; resume from highest committed offset; write to `.part`, `MoveFileEx` on commit. |
| **Processes** | `NtQuerySystemInformation` for the fast list; enrich on demand | CPU% from sampling `GetProcessTimes` twice; command line/owner/elevation lazily via `OpenProcess` + token queries (SYSTEM has `SeDebugPrivilege`, so cross-session works). `sysinfo` crate is a reasonable shortcut. |
| **Services** | `EnumServicesStatusExW`, `OpenSCManager`, `ControlService`, `ChangeServiceConfig` | Fully documented; the `windows-service` crate wraps it. |
| **Registry** | `RegOpenKeyExW` + family | Preserve raw type+bytes so the UI renders `REG_MULTI_SZ`/`REG_BINARY` correctly; expose a 32/64-bit view toggle (`KEY_WOW64_64KEY`/`32KEY`); a specific user's `HKCU` = open `HKU\<SID>` if logged on, else `RegLoadKey` their `NTUSER.DAT` (and **guarantee unload** or you corrupt the profile). |
| **Event log** | `EvtQuery`/`EvtNext`/`EvtRender` (wevtapi) | Modern API reaches all channels; filter with XPath in the query, never pull-then-filter; `EvtSubscribe` for live tail. Query handle is thread-affine. |

**High-value additions:** installed programs (Uninstall registry keys, *not* `Win32_Product`),
scheduled tasks (Task Scheduler 2.0 COM), network config/connections (`GetAdaptersAddresses`,
`GetExtendedTcpTable` with owning PID), disk/SMART health (`MSFT_PhysicalDisk` +
`MSStorageDriver_FailurePredictStatus` via WMI), Windows Update status, local users/groups,
startup items, environment variables.

### Privilege model (shared by shell and all panels)

The agent is LocalSystem, which holds every privilege you need. Run each operation under a
**selectable token**:

- **As SYSTEM** — deep maintenance (services, registry, drivers). `CreateProcess` inherits
  the service token.
- **As the logged-in user** — when you need their profile, `HKCU`, or network identity:
  `WTSQueryUserToken(sessionId)` → `DuplicateTokenEx(...TokenPrimary)` →
  `CreateEnvironmentBlock` (from the *target* token, or the child gets SYSTEM's environment)
  → `CreateProcessAsUser`. For an already-logged-on user the profile is loaded; only call
  `LoadUserProfile` otherwise.
- **As supplied credentials** — `LogonUserW` (prefer `LOGON32_LOGON_BATCH` for service-
  driven logons) then the same `CreateProcessAsUser` chain. Prefer this over
  `CreateProcessWithLogonW`, which routes through the Secondary Logon service and doesn't
  cleanly work from LocalSystem. **This is a lateral-movement primitive — gate it hardest.**

---

## Part 2 — The hidden GUI desktop (optional, later, scoped)

If you build the real hidden-desktop feature, the naive design you'd first reach for is
**wrong on all three of its legs**. This is the crux research finding, triangulated across
the ReactOS win32k source, documented API behavior, the RPA/RDP "locked machine" industry
pain point, ConnectWise's own patent, and 10+ years of HVNC tooling.

| The obvious approach | Reality | What actually works |
|---|---|---|
| `SendInput` to drive the desktop | **Hard-fails** on a non-input desktop (`ERROR_ACCESS_DENIED`). There's one Raw Input Thread per *session*, and only the `SwitchDesktop`-active desktop receives synthesized input. | `PostMessage`/`SendMessage` of `WM_MOUSE*`/`WM_KEY*`/`WM_CHAR` to specific window handles, plus a **hand-built window manager** (enumerate windows, track z-order, hit-test the cursor, synthesize focus and modifier state yourself). |
| DXGI Desktop Duplication or WGC to capture it | **Cannot** — both capture the *displayed* scanout, which is always the input desktop. DWM only composites the primary desktop. | `PrintWindow` per top-level window (with the undocumented `PW_RENDERFULLCONTENT` flag) + **software z-order composition**, drawing bottom-most first. This is verbatim what ConnectWise's patent describes. |
| Rely on Explorer being present | No shell by default — the shell window is per-desktop, so a new desktop has no taskbar/Start/tray. | Launch tools directly onto the desktop via `STARTUPINFO.lpDesktop`; run a **tiny custom launcher window** as a makeshift shell (ScreenConnect ships `ScreenConnect.WindowsBackstageShell.exe`, which is why Backstage "looks plain"). |

### The deep catch that defines the feature's scope

**`PrintWindow` and `PostMessage` fail on the same class of apps** — GPU/DirectX/Chromium/
Electron/games render as **black frames** on capture *and* ignore posted input (they read
`WM_INPUT`/`GetAsyncKeyState`, which reflects session-global state you can't set). Standard
Win32/GDI admin tools — PowerShell, cmd, RegEdit, MMC, Services, Event Viewer, Task Manager
— sit on the *good* side of **both** lines. That is not a coincidence; it's exactly why
Backstage is scoped to admin tools and is **not** a general-purpose second desktop for
arbitrary apps. Design to that scope: detect black `PrintWindow` output and show a "this app
can't be displayed in background mode" affordance rather than pretending it works.

### Two viable architectures

- **HVNC-style (simpler, recommended if you build this):** `CreateDesktop` a hidden desktop
  *inside the logged-in user's session*, launch tools there, `PrintWindow`-capture,
  `PostMessage`-inject. Runs as the user (or SYSTEM if launched that way). Avoids all the
  Session 0 input-hostility caveats.
- **Backstage-style (what ConnectWise patented):** flip **Session 0** interactive via a
  registry key (`NoInteractiveServices`) and host the desktop there as SYSTEM. More complex,
  more session-0-isolation caveats, and note ConnectWise holds **US patents 11,582,287 and
  12,289,359** on the hidden-desktop-in-a-hijacked-system-session approach — a reason to
  prefer the HVNC-style user-session route, which is well-trodden prior art.

### Non-obvious constraints

- **A Session 0 service cannot create a desktop in the user's session** — cross-session
  `OpenWindowStation`/`SwitchDesktop` fail. Use a two-stage launch: service →
  `CreateProcessAsUser` a helper into the user's session → helper does `CreateDesktop` and
  launches tools.
- **There is no `DestroyDesktop`.** A created desktop persists until logoff. **Reuse one
  desktop; never create one per connection** — desktop heap is finite (~48 MB system-wide,
  ~3 MB per desktop).
- **UAC prompts render on the Winlogon secure desktop**, a different desktop your
  `PrintWindow`/`PostMessage` can't touch. Running tools already-elevated as SYSTEM sidesteps
  this (no UAC prompt at all).
- **Never call `SwitchDesktop` or `LockWorkStation` against the user's live desktop** on
  teardown — ScreenConnect had a bug (fixed v23.2) that locked the user's screen when
  Backstage ended. Clean up tool processes, ACEs, and any registry keys instead.
- **If you ever need full-fidelity control of arbitrary GPU apps** unseen by the user, the
  desktop primitive is the wrong tool — the right one is a **separate session** (RDS
  multi-session), where `SendInput` and DDA both work normally. That's a different, larger
  feature.

---

## Security, audit, and ethics — non-negotiable for this feature set

These channels are effectively unrestricted SYSTEM-level RMM. The blast radius is total:
killing `lsass` BSODs the machine, a bad registry edit bricks it, a failed `RegUnLoadKey`
corrupts a profile. Treat the control plane accordingly.

- **Per-capability RBAC, not all-or-nothing.** Tier it: read-only (view processes/services/
  events, browse+download files) → operator (restart services, kill non-critical processes,
  user-context shell) → admin (registry write, SYSTEM/arbitrary-credential shell, hive
  load/unload, service config, delete/uninstall). Gate every RPC method server-side; never
  trust the UI to hide a button.
- **Hardcoded protected-object denylist** in the agent: refuse to kill critical processes
  (`lsass`, `csrss`, `wininit`, `services`, `smss`, the agent itself) and refuse to stop the
  agent's own service. Require type-the-machine-name confirmation for the truly dangerous
  ops (registry writes under `HKLM\SYSTEM`, service ImagePath edits, hive unload).
- **Mandatory, tamper-evident, off-box audit.** Every session (who, which machine, when,
  source IP); **full shell transcripts including which token the shell ran under**; every
  mutating op with before/after where feasible; credential-*use* events (never the password).
- **Credential hygiene:** supplied passwords in memory only, zeroized after `LogonUser`
  (Rust `zeroize`), never logged or persisted.
- **Consent and visibility are the line between a support tool and a RAT.** ScreenConnect
  *restricted* hiding the tray icon and connection banner in 2025 specifically because the
  hidden-desktop capability was being abused in tech-support scams. Match that stance:
  policy-gate unattended/background access, keep it audit-visible, and **never ship a mode
  designed to hide the tool from the machine's owner.** Both AV vendors and buyers judge you
  on exactly this.
- **Expect AV/EDR friction** on the hidden-desktop feature specifically — it is
  behaviorally identical to HVNC malware and Defender ships detection for it. This is
  another reason to lead with headless panels and gate the GUI desktop carefully.
- **Capabilities to reconsider shipping at all:** copying `SAM`/`SECURITY`/`ntds.dit`
  (credential-theft optics) and a generic read-any-process-memory primitive (high abuse,
  low support value). I'd omit both.

---

## Recommended sequencing

1. **ConPTY interactive shell** (user-context and SYSTEM, selectable). Highest value-to-
   effort ratio in the whole backstage feature set, and it's fully documented and low-risk.
2. **Read-only panels** — processes, services, event log, file browse/download. Immediately
   useful, low blast radius.
3. **Mutating panels** — service control, registry edit, file upload/delete, process kill —
   behind the RBAC tiers and audit above.
4. **The rest of the headless tools** — scheduled tasks, installed programs, network, disk
   health, users/groups, etc.
5. **Hidden GUI desktop (HVNC-style)** — only after the panels are solid, scoped explicitly
   to admin GUI tools, with the black-frame detection affordance and heightened AV posture.

This ordering front-loads the value (a real remote shell and live system panels) and defers
the hardest, riskiest, most AV-sensitive piece until it's genuinely warranted.

---

## Key references

- ConnectWise patents US 11,582,287 B2 and US 12,289,359 B2 — "Hidden desktop session for
  remote access" (the `PrintWindow` + z-order composition + Session 0 interactivity mechanism)
- ReactOS win32k source — `NtUserSendInput` desktop gating, `DESKTOPINFO.hShellWindow`
- Microsoft docs — Window Stations and Desktops, ConPTY, `WTSQueryUserToken` /
  `CreateProcessAsUser`, `EvtQuery`, `PrintWindow`
- Sysinternals Desktops (Russinovich) — per-desktop Explorer, no-DestroyDesktop, heap limits
- HVNC prior art — MalwareTech/HiddenDesktop, WKL-Sec/HiddenDesktop; DeepSec 2017 "Who Hid
  My Desktop"
- Microsoft Defender for Endpoint — detection of processes on hidden desktops
