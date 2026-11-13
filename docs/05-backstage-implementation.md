# Backstage Implementation — Scaffold Notes

This documents the starter code under [`agent/`](../agent/), which implements the **headless
backstage** surface from [04-backstage.md](04-backstage.md). The GUI hidden desktop is
deliberately deferred.

> **Status: builds green on Windows (Rust 1.97); the full backstage tool surface is
> implemented and the interactive shell is verified working end-to-end.** `cargo test` passes
> 51 tests (2 mutation/console tests are `#[ignore]` — see below). **Five read-only panels**
> run live through the capability-checked, audited dispatcher — process (`sysinfo`), service
> list (`EnumServicesStatusEx`), system info (`sysinfo`), event log (`EvtQuery`, verified
> against the real System channel), and file browse (`std::fs`). **Three mutating ops** run
> through the same choke point with real, tested OS calls — process kill (`TerminateProcess`,
> verified by killing a spawned child), registry read/write (`winreg`, verified round-trip
> under HKCU with before/after capture), and service control (`ControlService`, error paths
> tested; live restart is `#[ignore]`). A **live PowerShell session over WebSocket** is routed
> through the dispatcher (`open_shell`: capability → `ShellOpen` audit → spawn), verified via
> `shell_server` + `ws_probe`. The audit chain uses real **SHA-256** (`sha2`). The remaining
> stub is the production `token::acquire` (run-as-user / SYSTEM / credential), which needs a
> security review before wiring; the demo shell runs as the current user.

## Layout

```
agent/
  Cargo.toml                         deps: windows, sysinfo, conpty, axum, tokio-tungstenite
  src/
    lib.rs                           crate root
    backstage/
      mod.rs        Dispatcher — the enforced choke point (cap → guard → confirm → exec → audit)
      rbac.rs       Capability enum, Grant, GuardRail, protected-object denylists   [portable]
      audit.rs      AuditEvent, hash-chained AuditChain, verify_chain               [portable]
      token.rs      Identity → primary token + env (WTSQueryUserToken path)         [windows]
      shell.rs      ConPTY shell session (via conpty crate) + Send split-halves     [windows]
      panels/                          READ-ONLY tool panels (Tier-1), all RUN through the dispatcher
        process.rs  Process list over sysinfo                                        [portable]
        services.rs Service list over EnumServicesStatusEx                           [windows]
        sysinfo.rs  Machine identity + resource summary over sysinfo                 [portable]
        eventlog.rs Event-log channel view over EvtQuery/EvtRender                   [windows]
        file.rs     Filesystem browse over std::fs (GetLogicalDrives roots)          [portable]
      ops/                             MUTATING ops (Tier-2/3), behind cap + guard + confirm + audit
        process.rs  Process kill over OpenProcess/TerminateProcess                   [windows]
        registry.rs Registry read/write over winreg (before/after capture)          [windows]
        service.rs  Service start/stop/restart over ControlService                   [windows]
    transport/
      shell_ws.rs      Shell WebSocket wire codec (data/resize/close/exit) — tested [portable]
      shell_authz.rs   WHO may open a demo server's socket: per-run token + Host/Origin [portable]
      shell_server.rs  axum bridge: browser terminal <-> dispatcher-gated ConPTY    [windows]
      backstage_api.rs JSON request/response bridge: dispatch_json + axum adapter    [portable]
  bin/
    shell_server.rs                  Runs the shell bridge on http://127.0.0.1:8071  [--insecure-dev]
    backstage_server.rs              Runs the panel/op JSON API on http://127.0.0.1:8072 [--insecure-dev]
    ws_probe.rs                      Headless WS client that verifies a shell round-trip
      ^ all three are INSECURE DEV DEMOS and never ship. `Assert-NoDemoBinariesShipped`
        derives its denylist from this directory, so a binary added here is covered at once.
  examples/
    list_processes.rs                Runnable demo: live process data via the dispatcher
    list_services.rs                 Runnable demo: live service data via the dispatcher
    browse_dir.rs                    Runnable demo: live directory listing via the dispatcher
  assets/
    terminal.html + vendor/          Self-contained xterm.js terminal page
  migrations/
    0001_backstage_audit.sql         Postgres audit schema with tenant_id + RLS
```

`[portable]` modules compile and test on any host. `[windows]` modules are `#![cfg(windows)]`.

## Verify it yourself

```
cd agent
cargo test                            # 56 tests: RBAC, guard rails, SHA-256 audit chain, panels, ops, wire codec
cargo run --example list_processes    # prints live top-15 processes + an audit record
cargo run --example list_services     # prints live services (state + host PID) + an audit record
cargo run --example browse_dir "C:\\" # prints a live directory listing + an audit record (path in the audit)

# BOTH DEMO SERVERS NOW REQUIRE --insecure-dev AND A PER-RUN TOKEN (docs/25 F16).
# They used to accept every caller that could reach their loopback port, which handed a
# PowerShell (8071) and file-browse + registry-read (8072) to any process on the machine, and
# potentially to a web page — loopback is not an authorization boundary. Each mints a fresh token
# at startup, prints the exact command/URL carrying it, checks Host and Origin, and dies with it.
# Neither is ever shipped: a packaging guard fails the build if either reaches an artifact.

# Backstage panel/op JSON API (drives every read-only panel through the dispatcher):
cargo run --bin backstage_server -- --insecure-dev   # listens on http://127.0.0.1:8072
#   It prints a ready-made curl line; the token goes in a header or as ?t=<token>:
#   curl -s -H "Authorization: Bearer <token>" 127.0.0.1:8072/backstage/exec -d '{"type":"GetSystemInfo"}'
# A denied action returns a well-formed envelope: {"ok":false,"error":{"kind":"denied",...},"audit":{...}}
# An UNAUTHORIZED request never reaches the dispatcher at all: 403, and no audit record, because
# nothing was dispatched.

# Live interactive PowerShell in the browser:
cargo run --bin shell_server -- --insecure-dev   # then open the printed http://127.0.0.1:8071/?t=<token>
# Or verify headlessly (server must run in its own console window — see the ConPTY note):
cargo run --bin ws_probe -- "ws://127.0.0.1:8071/ws?t=<token>"
#   ...or put the token in RMT_SHELL_DEMO_TOKEN and run `cargo run --bin ws_probe` bare.
```

## The ConPTY-needs-a-console finding (learned the hard way)

A ConPTY child process attaches to **its host process's console**. If the host has no real
console — as under `cargo test`, or any harness that redirects stdio — the child fails to
attach and renders to the wrong place; the output pipe only ever carries ConPTY's own setup
bytes. This is **not** a code bug: it reproduces identically with the tested `conpty` crate
*and* with hand-rolled `CreateProcessW` FFI, and even the crate's own README example hangs
under capture.

Consequences, baked into the code:
- `shell_server` run as its own process (its own console) works perfectly — verified with
  `ws_probe`: the transcript shows the PowerShell prompt, the echoed command with syntax
  highlighting, and its output.
- The **production agent runs as a Windows service (session 0, console-less)**, where ConPTY
  is fully supported — this is the normal, documented environment for it.
- The two tests that need a live child console (`conpty_interactive_roundtrip` and the
  `shell_e2e` integration test) are `#[ignore]` with an explanation; run them from a real
  console with `cargo test -- --ignored`. Everything else runs in CI unconditionally.

## The one thing to take away: a single enforced path

Every backstage request goes through [`Dispatcher::handle`](../agent/src/backstage/mod.rs) in
a fixed order that must never be reordered:

1. **Capability check** — does the technician's signed grant include the required capability?
2. **Guard rail** — is this specific target on the protected denylist (refuse) or extra
   dangerous (require typed confirmation)?
3. **Confirmation gate** — machine-name confirmation for sensitive targets and for
   always-confirm capabilities (supplied-credential shell, hive load, uninstall).
4. **Execute** — the actual OS work.
5. **Audit** — *always*, including on denial. A blocked attempt is itself a record.

There is no second path to the tool implementations. The tests in `mod.rs` assert the
invariants directly: an ungranted kill is denied and audited; killing `lsass` is refused even
*with* the capability; a write under `HKLM\SYSTEM\...\Services` needs confirmation.

## Why the code is shaped this way

- **RBAC is per-capability, not per-role.** Roles are resolved server-side into a list of
  capabilities; the agent only ever sees the capability list. Adding a capability is an
  explicit enum change, so an unknown capability can never be granted implicitly.
- **The agent never trusts the UI.** Hiding a button is cosmetic; the dispatcher re-checks
  every request. This matters because the transport is attacker-reachable.
- **Audit is hash-chained.** Each event carries the previous event's hash, so deletion,
  reordering, or after-the-fact edits are detectable (`verify_chain`). The placeholder hash
  in `audit.rs` is an FNV stand-in labeled DO-NOT-SHIP — swap for SHA-256 (`sha2`) and
  consider signing each event with the agent's device key.
- **Shell identity is recorded, secrets are not.** `AuditAction::ShellOpen` records whether a
  shell ran as SYSTEM, a named user, or supplied credentials; `CredentialUse` records the
  principal, never the password (held in `Zeroizing`, wiped after `LogonUser`).
- **The shell is an allowlist, not arbitrary exec.** `shell.rs` launches only
  `powershell.exe`/`cmd.exe`. Don't let the shell channel become a way to run arbitrary
  binaries that bypass the per-tool capability checks.

## ConPTY specifics worth remembering (shell.rs)

- The agent is a **byte relay** — ConPTY emits/consumes VT, xterm.js is the emulator. No ANSI
  parsing on the agent.
- `shell.rs` uses the tested **`conpty` crate** for the pseudoconsole primitive, and adds the
  `split()` shape (reader / writer / control halves). Note `conpty::spawn(&str)` wraps input
  in `cmd /C` — use `Process::spawn(std::process::Command)` to launch PowerShell with args.
- The `conpty` types are `!Send` (they retain raw pointers); each split half is exclusively
  owned by one thread and moved (never shared), so `unsafe impl Send` on the halves is sound.
- conpty's pipe read can return transient `WouldBlock` — treat it as "no data yet", not EOF,
  or the reader thread dies after the first burst.
- Forward output to the browser as **binary** WebSocket frames; ConPTY output can split UTF-8
  across reads, so let xterm.js's decoder reassemble.
- ConPTY needs the host process to own a real console — see the finding above.
- Requires Win10 1809+ (build 17763) — every supported Windows.

## What's real vs. still stubbed

| Location | State | Notes |
|---|---|---|
| `shell.rs` ConPTY session + split halves | **works** | Verified live over WebSocket via `ws_probe`. |
| `mod.rs` `open_shell` (dispatcher-gated shell) | **works** | Shell now flows through the choke point: capability → `ShellOpen` audit → spawn. `ws_probe` still round-trips. |
| `transport::shell_server` + `shell_ws` codec | **works** | Browser terminal bridge, routed through the dispatcher; codec unit-tested. |
| `panels::process` | **works** | Live data through the dispatcher. |
| `panels::services` | **works** | Live service list (state + host PID) via `EnumServicesStatusEx`, through the dispatcher. |
| `panels::file` | **works** | Live filesystem browse via `std::fs`; top level uses `GetLogicalDrives` (no media probing). Records the browsed path in the audit. |
| `rbac` / `audit` / dispatcher enforcement | **works** | 35 passing tests assert the invariants. |
| `audit.rs` hash | **SHA-256** | Real `sha2::Sha256` over the canonical preimage; a known-vector test guards against regressing to a stand-in. Signing each event with the device key is a later hardening step. |
| `token.rs` `acquire(LoggedInUser)` | written, not yet called | The demo shell runs as the current user via `CreateProcessW` inside conpty; wiring the token path swaps in run-as-user/SYSTEM. `conpty::Process::spawn` can't take a custom token, so the swap lands with the service-hosted launcher. |
| `token.rs` `acquire(Credential)` | `unimplemented!` | Most dangerous path (lateral-movement primitive). Needs its own security review before wiring — see 04-backstage.md. |
| `mod.rs` `execute` (kill / service control / registry) | returns an error | Mutating-tool bodies attach here; the enforcement path around them already gates them. |

## Next steps to make it real

Done: toolchain up, crate builds, 35 tests green, **three read-only panels running through the
dispatcher** (process / service / file browse), a **SHA-256** audit chain, a **live PowerShell
session over WebSocket now routed through the dispatcher** (`open_shell`: capability →
`ShellOpen` audit → spawn), verified end-to-end (`shell_server` + `ws_probe`).

Completed from the original list:
- ~~Replace the FNV placeholder in `audit.rs` with SHA-256.~~ Done (`sha2`, known-vector test).
- ~~Route the shell channel through the `Dispatcher`.~~ Done via `Dispatcher::open_shell`.
- ~~Read-only panels: service list, file browse, plus system info and event log.~~ Done — the
  whole Tier-1 read surface (`panels::{process,services,sysinfo,eventlog,file}`).
- ~~Mutating panels: process kill, registry read/write, service control.~~ Done — the
  `backstage::ops` module, wired into `Dispatcher::execute` behind Tier-2/3 + guard rail + audit.

Remaining, in order:

1. Wire `token::acquire(LoggedInUser)` / `System` so the shell runs as the logged-in user or
   SYSTEM instead of the current process. Requires the service-hosted launcher:
   `CreateProcessAsUser` + the `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` attribute (conpty's
   `Process::spawn` doesn't accept a token). `open_shell` already records the requested
   identity, so only the process-creation step changes.
2. Run the agent as a **Windows service** (the console-less environment ConPTY expects) and
   drive the backstage channel through the relay instead of the demo loopback server.
3. A **backstage wire protocol** so the web console can actually invoke the panels/ops: serde on
   `Request`/`Response` + a channel message + a bridge server. (The web viewer already renders
   the panel row shapes; this is the connective tissue.)
4. Fidelity + breadth follow-ups: record registry before/after in the audit action itself (the
   op already returns the prior value); the localized event-log message via `EvtFormatMessage`;
   DWORD/binary registry values; file upload/download/delete ops (Tier-2/3).
5. Security review specifically of the supplied-credential path before enabling it.
6. Forward the audit chain to the relay for per-tenant persistence (the demo currently logs it).

This ordering matches the roadmap's backstage sequence in [03-roadmap.md](03-roadmap.md).
