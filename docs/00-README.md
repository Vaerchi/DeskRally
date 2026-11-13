# DeskRally — Planning Docs

A Windows-first remote support and unattended access product, architected for
cross-platform expansion, deployable as both a self-hosted appliance and a multi-tenant
SaaS from one codebase.

The product was renamed from Bridge to DeskRally. Code namespaces remain `rmt`.
Examples use `console.example.com`; deployment hostnames are configurable.

## Documents

The exported documentation covers architecture, deployment, agent behavior and session design.
Start with the [agent deployment guide](guides/client-deployment.md) or
[connection troubleshooting](connection-troubleshooting.md).

| Document | Contents |
|---|---|
| [02-architecture.md](02-architecture.md) | Architecture & Technology Decisions |
| [18-selfhost-deployment.md](18-selfhost-deployment.md) | Self-hosting on one Linux box, exposed to the internet |
| [32-msi-provisioning-and-testing.md](32-msi-provisioning-and-testing.md) | Configuration-aware MSI — unsigned testing round |
| [33-agent-auto-update.md](33-agent-auto-update.md) | Agent auto-update (MSI 1.3.x) |
| [34-console-sso.md](34-console-sso.md) | Console single sign-on (Microsoft Entra ID), phase 1 |
| [49-session-lease-reaper.md](49-session-lease-reaper.md) | ending leaked session rows from the agent's own end report |
| [50-agent-turn-over-tcp-tls.md](50-agent-turn-over-tcp-tls.md) | Agent TURN over TCP and TLS |
| [52-dxgi-composite-capture.md](52-dxgi-composite-capture.md) | 52 — Composite capture from persistent per-output DXGI duplications |
| [53-attended-elevation.md](53-attended-elevation.md) | 53 — Attended sessions: request admin rights mid-session |
| [58-backstage-file-management.md](58-backstage-file-management.md) | Backstage file management and "silent operations" |
| [61-input-handoff.md](61-input-handoff.md) | Handing input control between technicians inside one session (design) |
| [62-subgroups.md](62-subgroups.md) | Nested machine subgroups with downward-inherited access (design) |
| [64-guest-help-requests.md](64-guest-help-requests.md) | Guest-initiated help requests from enrolled machines (design) |
| [04-backstage.md](04-backstage.md) | Backstage design |
| [05-backstage-implementation.md](05-backstage-implementation.md) | Backstage implementation |
| [44-managed-installer-deployment.md](44-managed-installer-deployment.md) | Managed installer deployment |
| [51-session-transfer.md](51-session-transfer.md) | Session transfer |
| [56-expiring-access.md](56-expiring-access.md) | Expiring access |
| [57-scheduled-access-windows.md](57-scheduled-access-windows.md) | Scheduled access windows |
| [65-fleet-agent-directives.md](65-fleet-agent-directives.md) | Fleet agent directives |
| [agent-update.md](agent-update.md) | Agent updates |
| [change-login-email.md](change-login-email.md) | Login email changes |
| [cli-recording-service.md](cli-recording-service.md) | Recording service |
| [connection-troubleshooting.md](connection-troubleshooting.md) | Connection troubleshooting |
| [design-shared-toolbox.md](design-shared-toolbox.md) | Shared toolbox |
| [desktop-remembered-sign-in.md](desktop-remembered-sign-in.md) | Remembered sign-in |
| [guest-chat-window.md](guest-chat-window.md) | Guest chat |
| [client-deployment.md](guides/client-deployment.md) | Agent deployment |

## The short version

**Stack:** Rust agent · Go signaling and relay · React web console and viewer ·
PostgreSQL with row-level security · WebRTC transport (QUIC as a v2 native fast path).

**The three decisions that matter most:**

1. **Rust agent with a platform-abstracted core crate, and the service + per-session
   SYSTEM helper architecture done right on day one.** Trust, cross-platform expansion, and
   secure-desktop capture all depend on it.
2. **WebRTC as the v1 transport backbone**, behind a clean channel abstraction. It hands
   you the browser viewer, NAT traversal, encryption, and adaptive bitrate in one stack —
   the biggest single de-risking move available at MVP.
3. **One PostgreSQL schema with `tenant_id` + RLS, where self-hosted is simply one tenant
   row.** This is what makes "self-hosted and SaaS from one codebase" true rather than a
   slogan.

**The first thing to build:** a spike proving you can capture and click through a Windows
UAC prompt remotely. It's the highest-risk unknown in the project, and if the approach
doesn't hold, the architecture needs to change before anything is built on it.

**The strategic caution:** full parity is roughly two decades of ConnectWise engineering.
Aim for competitive
sufficiency on the core workflows MSPs use daily, then differentiate.

**On backstage specifically:** the market word "backstage" covers two different things.
Nearly every competitor ships **headless tool panels** (system data rendered in the
technician's UI); only ScreenConnect (and, partially, NinjaOne) ships a true **hidden
interactive GUI desktop**, whose mechanism is the same Windows primitive family as HVNC
malware. Lead with the panels — they cover most real use, feel faster, and are far less
AV-sensitive — and treat the hidden GUI desktop as an optional, scoped, later addition.
See [04-backstage.md](04-backstage.md).
