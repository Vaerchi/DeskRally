# Architecture & Technology Decisions

Windows-first agent, cross-platform-capable core, deployable as **both** a self-hosted
single box and a multi-tenant SaaS from one codebase.

---

## Recommended stack

| Layer | Choice | Why |
|---|---|---|
| **Agent** (controlled endpoint) | **Rust** | No runtime, small static binary, memory-safe at SYSTEM privilege, direct Win32 via the official `windows` crate, real cross-platform path. Validated by RustDesk. |
| **Signaling / rendezvous** | **Go** | Tens of thousands of mostly-idle long-lived connections is goroutine-shaped work. Best productivity-per-engineer, excellent ops story. |
| **Relay (data plane)** | **Go** (Pion) + **coturn** | Dumb, stateless, E2E-blind byte forwarder. Trivially horizontally scalable. |
| **Web console + viewer** | **React + TypeScript + Vite + Tailwind**, shadcn/ui | Deepest hiring pool for a product you'll maintain for a decade. |
| **Technician desktop app** | Browser-only for MVP → **Tauri** later | Tauri shares Rust crates with the agent and the React viewer. Avoid Electron. |
| **Database** | **PostgreSQL everywhere** | See ADR-003 — do *not* ship SQLite for on-prem. |
| **Cache / presence** | Redis (cloud), embedded equivalent on-prem | |
| **Auth** | **Zitadel** embedded, or own auth core + OIDC/SAML SP | Multi-tenant-native, ships as a Go binary into both modes. |

### Deliberate non-choices
- **No kernel driver.** DDA + WGC + `SendInput` + `SendSAS` cover everything mirror drivers
  used to. No driver means no WHQL, no boot-time attack surface, and far fewer EDR alerts.
  Only revisit for virtual displays or USB redirection.
- **Not .NET for the agent**, despite ScreenConnect using it. The agent is the component
  you least want a runtime dependency or GC in. Reconsider only if the team is deeply
  .NET-native and time-to-market strictly dominates.
- **Not Go for the agent** — GC, larger idle footprint, painful cgo boundary for heavy
  Win32/DXGI interop.
- **Not Node for signaling** — single-threaded event loop, weak at large fan-out.

---

## ADR-001: Transport — WebRTC first, QUIC as a planned v2 native fast path

**This was the one genuine disagreement in research and it deserves a clear ruling.**

The case for **QUIC**: independent streams eliminate head-of-line blocking between
channels (a stalled 2 GB file transfer never delays a keystroke), the DATAGRAM extension
gives exactly the partial reliability live video wants (drop stale frames rather than
retransmit them), connection migration survives Wi-Fi↔cellular roaming, and you own the
whole stack. RustDesk and Parsec both hand-roll transports for these reasons.

The case for **WebRTC**: it bundles ICE/STUN/TURN, DTLS-SRTP, congestion control, and
adaptive bitrate into one mature stack — and critically, **it is the only one of the two a
browser can speak natively**, giving you hardware-accelerated decode in the browser for free.

**Decision: build v1 on WebRTC**, behind a transport abstraction, and add QUIC as a native
agent↔controller fast path in v2.

Reasoning: the browser controller is a first-class requirement for MSP technicians, not a
nice-to-have. WebRTC delivers the browser path, NAT traversal, encryption, and congestion
control in a single stack — that is the largest single de-risking move available at MVP.
QUIC's advantages are real but are *optimizations*, and optimizations should not gate a
working product. Parsec spent roughly three years tuning its custom congestion control;
that is not the right first investment for an IT-support tool where WebRTC's latency is
already sufficient.

**The obligation this creates:** define a `Transport` trait with explicit named channels
and per-channel reliability/priority policy on day one. If the channel abstraction is
clean, swapping in QUIC later is contained. If it isn't, this decision becomes permanent
by accident. Treat that abstraction as load-bearing, not incidental.

## ADR-002: Split control plane from data plane

Copy RustDesk's hbbs/hbbr separation regardless of transport:

- **Rendezvous/signaling** — authoritative, authenticated. Holds `{device_id → address,
  pubkey, NAT type, last-seen}`. Brokers sessions. Decides *which controller may reach
  which agent*. Low bandwidth, connection-bound.
- **Relay** — deliberately dumb. Pairs two half-connections by session UUID and forwards
  ciphertext. Holds no decryptable state, so it scales as a stateless fleet and is safe to
  share across tenants.

Agents get **stable IDs, not IPs**. The server brokers; peers never self-dial (even for
direct P2P, offer/answer routes through signaling).

**Ship both roles in one binary with a `--role` flag** so self-hosters run one process.

## ADR-003: One PostgreSQL schema with row-level security

Contrarian but firmly held: **do not ship SQLite for self-hosted.**

Two databases means two SQL dialects, two migration paths, two bug surfaces, and features
that work in one deployment mode but not the other (RLS, JSONB, `LISTEN/NOTIFY`,
concurrent writers). That tax compounds forever.

Instead, ship self-hosted as an **appliance** with a pinned embedded Postgres. The admin
never manages Postgres — it's as invisible as SQLite would have been.

**Tenant isolation:** shared schema, `tenant_id` on every tenant-scoped table, enforced by
PostgreSQL **Row-Level Security**. Every request sets `app.current_tenant`; RLS makes
cross-tenant reads impossible even when application code has a bug. For a system holding
multiple MSPs' access to their clients' machines, that safety net is the single most
important data-layer decision.

**Self-hosted is exactly one tenant row.** Same code, same schema, no `if self_hosted`
branches. A `DEPLOYMENT_MODE` flag toggles tenant-provisioning UI and billing only.

Reserve schema- or database-per-tenant for the handful of enterprise customers who
contractually demand physical separation — as a routing layer on top, not the default.

Keep audit/session/metrics time-series in partitioned tables so audit volume never degrades
the console.

## ADR-004: End-to-end encryption, relay-blind

> **STATUS (2026-08-30): points 2, 3 and 5 below are DESIGN, NOT SHIPPED.** Verified by audit, not
> assumed — `crates/crypto`'s `Handshake`/`SessionKeys` are real code that **no shipping binary
> instantiates** (`Session::new` appears only in tests), and `peer_pubkey` arrives on `brokered` and
> is **discarded** by every non-test match arm in `transport-webrtc`. Nothing is pinned.
>
> **What IS true today:** session traffic rides a WebRTC data channel, so it is SCTP-over-DTLS
> peer-to-peer, and the relay forwards bytes it cannot read. In-transit confidentiality is real.
>
> **What is NOT true today:** the app-level layer that would keep content opaque *independently* of
> the transport, and the key pinning of point 5. SDP — carrying the DTLS fingerprints — is exchanged
> through signaling, and because `peer_pubkey` is never verified, **a compromised signaling server
> could substitute fingerprints and MITM a session.** That is precisely the malicious-rendezvous gap
> point 5 exists to close, and it is open.
>
> This section is kept as the target design. **Do not cite it as a description of current
> behaviour**, and do not repeat its claims to a customer until the code catches up.

Follow RustDesk's model, and close the gap it's been criticized for:

1. **Long-term identity:** Ed25519 keypair per agent and per user, registered at signaling.
2. **Per-session ephemeral key exchange:** X25519 ECDH authenticated by the long-term keys
   → forward secrecy, rotated per session.
3. **Layer app-level E2E *inside* the transport tunnel.** DTLS/TLS terminates at the relay
   when relayed, so the relay must see only ciphertext at the application layer.
4. **Never let the server hold session content keys.**
5. **Close the malicious-server gap:** a compromised rendezvous server could substitute
   public keys and MITM. Mitigate with key pinning / trust-on-first-use plus an
   out-of-band fingerprint the technician can verify. This is exactly the point RealVNC's
   security writeup flags against RustDesk — do better than the reference implementation.

**Browser caveat, to be stated honestly to customers:** if the browser path goes through a
gateway that terminates crypto, browser sessions are encrypted in transit but decrypted at
the gateway. Native-to-native is relay-blind E2E; browser sessions are not. Document this
distinction rather than blurring it in marketing.

## ADR-005: Windows agent — service + per-session SYSTEM helper

**Get this right on day one; it is the thing cheap clones get wrong.**

Services run in Session 0 and cannot touch the user's desktop. The secure desktop
(Winlogon — login screen, Ctrl+Alt+Del, UAC prompts) is a separate desktop object with a
restrictive DACL that even an in-session user helper can't reach.

```
LocalSystem Windows Service (Session 0, auto-start)
  ├─ persistent brain: relay connection, updates, reconnect, watchdog
  ├─ WTSGetActiveConsoleSessionId() → find active session
  └─ CreateProcessAsUser() with a SYSTEM token retargeted to that session
       └─ Per-session helper (SYSTEM, not the user)
            └─ Worker thread that follows the input desktop:
                 OpenInputDesktop() → GetUserObjectInformation(UOI_NAME)
                 → SetThreadDesktop() on change
                 → rebuild capture + input context
```

The helper must run as **SYSTEM**, not as the user, because only SYSTEM can
`SetThreadDesktop` onto Winlogon. This is non-negotiable for remote UAC control.

**Capture tiering:**
- **DXGI Desktop Duplication** primary — hands you an `ID3D11Texture2D` already in VRAM
  (zero-copy to the hardware encoder) *and* gives dirty rectangles natively via
  `GetFrameDirtyRects`/`GetFrameMoveRects`. That's the single biggest bandwidth win.
- **Windows.Graphics.Capture** — built, working, and **deliberately NOT in the tier chain**
  (2026-09-01). A WGC capture *permanently* prevents `SetThreadDesktop` on the calling thread
  (`ERROR_BUSY` 0x800700AA — a thread with windows or hooks cannot switch desktops), and dropping
  the capturer does not release it. That thread is the one that follows the input desktop *and* the
  one `SendInput` injects from, because both must be the same thread — so one WGC capture costs the
  agent every UAC prompt, lock screen and Ctrl+Alt+Del for the rest of the session, with capture
  frozen on the old desktop and every injected click landing there. It fired constantly, since DDA
  yields only on a screen change and any idle desktop fell through to it. Measured, with a DXGI
  control that passes, and pinned by
  `capture_wgc::tests::wgc_capture_permanently_disables_setthreaddesktop_on_that_thread`. Restoring
  it means running it on its OWN thread; until then GDI serves RDP.
- **GDI BitBlt** on the Winlogon secure desktop — DDA and WGC cannot capture it. Accept
  high-FPS DDA on Default, low-FPS GDI on secure desktop.

`DXGI_ERROR_ACCESS_LOST` fires constantly and is **normal** (desktop switch, resolution
change, DWM toggle, GPU reset). Treat recreate-on-ACCESS_LOST as a first-class state, not
an error path. A **timeout** is equally normal and is *not* the same thing: DDA yields a frame only
when the screen changes, so an idle desktop times out forever. Tearing the duplication down on a
timeout rebuilds it every ~100 ms for as long as nobody touches the machine.

**Multi-monitor: one id space, addressed BY RECT** (2026-09-01 — before this, a docked laptop with
three screens offered one in the picker).

The three tiers do not see the same displays and do not number them the same way:

| | enumerates | selects a monitor by | sees indirect displays (DisplayLink / USB dock / Miracast)? |
|---|---|---|---|
| DXGI | outputs, per adapter | flat output index | **no — not at all** |
| WGC | nothing | `HMONITOR` | yes |
| GDI | `EnumDisplayMonitors` | a rect to `BitBlt` | yes |

So **GDI's enumeration is authoritative** — it is the only one that sees every attached panel — and
ids are *positions* in that list, ordered left to right across the virtual desktop. A capture then
resolves an id to a **virtual-desktop rect**, and each tier addresses the panel at that rect: DXGI
duplicates the output whose `DesktopCoordinates` match (native, fast, and reports *no such output*
for an indirect display, which is the signal to fall through), WGC takes the `HMONITOR` at the
rect's centre, GDI blits the rect out of the desktop DC. The frame is always stamped with the
requested public id, never a tier's internal index.

The trap this avoids: publishing the GDI list while capture still selected "the Nth DXGI output"
streams the **wrong panel** for a given id — and every frame still looks like a perfectly valid
screen, so nothing downstream notices.

Three consequences worth knowing:
- Ids being positional means **the primary is not necessarily id 0** (a monitor placed left of it
  sorts first). Both the agent's initial selection and the viewer's picker read the `primary` flag,
  which is `left == 0 && top == 0` — the primary *defines* the virtual-desktop origin.
- `DuplicateOutput` is **adapter-bound**: the D3D device must live on the adapter that owns the
  output, or it fails with `E_INVALIDARG`. The capturer rebinds its device per monitor.
- **"View all" is one blit of the whole virtual desktop**, not a stitch of per-monitor captures.
  Alternating monitors makes DXGI recreate its duplication every call and a fresh duplication's
  first frame is blank, so the stitch came back black; and a left-to-right strip is not the real
  arrangement, whereas the virtual rect is exactly what `MOUSEEVENTF_VIRTUALDESK` normalizes
  against, so clicks land where they were aimed.

`agent_host monitors [--all-tiers] [--capture <dir>]` prints all of this for a real machine —
enumeration, DXGI outputs and their adapters, which tier serves each display, and a content
fingerprint that exposes the "captured the primary N times" failure.

**Input:** `SendInput` only — never `mouse_event`/`keyboard_event` (legacy shims) or
`SetCursorPos` (no buttons, subject to acceleration). Use
`MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK` with coordinates normalized 0–65535 across
the virtual desktop bounding box, computed in a **PerMonitorV2 DPI-aware** process.
Mixed-DPI fractional scaling is the #1 source of "cursor lands in the wrong place."

Ctrl+Alt+Del cannot be simulated — use `SendSAS()`, which requires the installer to set
`SoftwareSASGeneration` in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`.

**Service lifecycle:** `RegisterServiceCtrlHandlerEx` (the Ex variant is required for
session events) handling `SERVICE_CONTROL_SESSIONCHANGE` — console connect/disconnect
(fast user switching), logon/logoff, lock/unlock, remote connect/disconnect. Configure
`SC_ACTION_RESTART` failure actions plus a mutual service↔helper watchdog.

**Self-update:** a running service locks its own EXE. Download to staging → verify
Authenticode signature → launch a standalone updater EXE that stops, swaps, and restarts
the service. An unverified self-updater in a SYSTEM-level agent is a supply-chain backdoor
and an instant AV red flag.

## ADR-006: Encoding

DDA VRAM texture → hardware encoder, zero-copy: **NVENC / Intel Quick Sync / AMD AMF**.
H.264 baseline as the universal path; negotiate HEVC/AV1 when both ends have hardware
support. Software **OpenH264/VP9** fallback for RDP sessions and machines without a
hardware encoder.

Config that matters more than codec choice:
- Low-latency preset, **zero B-frames**, **infinite GOP with on-demand IDR** — request
  keyframes only on scene cut, packet loss, or a new viewer joining. Fixed short GOPs
  waste enormous bandwidth on a static desktop.
- Intra-refresh / slice-based rather than periodic full keyframes, to avoid bitrate spikes.
- CBR or capped-VBR driven by a network-feedback rate controller.
- **Dirty-rect-driven adaptive FPS**: on no dirty rects, drop to a heartbeat; ramp to
  30–60 FPS only when pixels move. This is the difference between a ~50 kbps idle desktop
  and a saturated link.
- Never buffer more than 1–2 frames anywhere in the pipeline.

## ADR-007: Channel multiplexing

One session, N named channels, one E2E key, priority-scheduled:

| Channel | Reliability | Ordering | Priority | Volume |
|---|---|---|---|---|
| Input events | Full | Strict | **Highest** | Tiny |
| Screen video | **Partial** (drop stale) | Loose | High | High/bursty |
| Clipboard | Full | Strict | Medium | Small |
| Chat / control | Full | Strict | Medium | Tiny |
| File transfer | Full | Strict per-file | **Lowest** | High |

File transfer must yield to video and input, or a large copy tanks the interactive session.
Chunk files with per-chunk checksums and resume support (offset + rolling hash). Encrypt
chunks with the session key so the relay never sees file contents.

---

## ADR-008: File transfer is grant-scoped and audits into the session's backstage chain

**Status:** accepted (2026-08-01). **Context:** `AuditAction::FileTransfer` existed in the agent's
audit vocabulary but nothing emitted it, because the tamper-evident `AuditChain` is constructed from
a backstage **grant** (`session_id`, `technician_id`, `machine_id` — see ADR-005/H1) and the
file-transfer channel had no grant context. Two designs were possible.

**Rejected — a separate session-level file-transfer trail.** The control plane stores the backstage
chain keyed `(tenant_id, session_id)` and `AppendAudit` verifies strict linkage against the stored
tail (`seq` contiguous, `prev_hash` matching). A *second*, independent chain for the same session
therefore **collides**: both would start at `seq 0` with an empty `prev_hash`, and the second batch
would be rejected as a broken chain. Making it work needs either a new table plus migration, or a
synthetic session id that severs the file transfer from the session it belongs to. That is more
machinery for a *weaker* result — the auditor loses the single ordered narrative of a session.

**Accepted — file transfer joins the session's existing chain, gated on the grant.** Three facts
make this the cheap and correct option:

1. `Capability::FileUpload` (operator tier) and `Capability::FileDownload` (read-only tier) **already
   exist** in the agent's RBAC model and are **already carried in every signed grant** — the control
   plane's `BackstageCapsFor` puts both in the read-only+operator baseline for any technician holding
   `backstage_shell`. So gating costs no protocol, canonical-encoding, or crypto change.
2. Events go into the **one** `AuditChain` the session's `Dispatcher` already owns, so the existing
   `POST /audit/ingest` path, its linkage verification, and its NDJSON SIEM export all keep working
   unchanged.
3. Forwarding rides the **file-transfer channel's own** new `Audit` control message rather than
   injecting an unsolicited envelope into the request/response backstage channel — channel
   discipline is preserved, and the browser surfaces the event through `FileTransferClient`'s
   `onAudit` hook, the exact counterpart of the `audit` field on a backstage `Envelope`.

**Where this stops today, stated precisely:** the agent emits the event and the browser client
exposes it; **the console does not yet ship it to `POST /audit/ingest`.** `AuditForwarder`
(`web/viewer/src/lib/audit_forward.ts`) is a built and tested seam that `App.tsx` never
instantiates — which has been true for the backstage chain since H2 and is not specific to file
transfer. So file transfer now has exactly the same forwarding status as every other backstage
action: recorded and chained on the agent, delivered to the controller, awaiting the one wiring step
in `App.tsx` (construct an `AuditForwarder` per brokered session, feed it both the backstage
envelopes and `onAudit`, flush on an interval and at teardown). Until then the trail is
tamper-evident but agent-local.

**Consequence, deliberate:** the file-transfer channel was previously **completely ungated** — any
peer reaching the data channel could read and write files under the transfer root with no capability
check and no record. It is now denied unless the session holds a verified grant carrying the
relevant capability. In **secure mode** (a grant issuer is configured) that means file transfer does
not work until `Control::InstallGrant` succeeds; in **dev mode** the self-issued full grant means no
behavioural change. This is a hardening, and it is the reason the ADR is worth writing down.

---

## Deployment topologies

**Self-hosted:** one binary (signaling + relay + web) + embedded Postgres + embedded
cache, in a Docker Compose bundle or a native Windows installer for shops that won't run
Docker. Zero external dependencies. This is a real differentiator against TeamViewer's
forced cloud, and matches ScreenConnect's on-prem pitch.

**SaaS:** stateless signaling fleet behind a load balancer with shared Redis presence
state; regional relay pools with geo/anycast routing; per-tenant authorization; metered
relayed bytes for billing. Because the relay is E2E-blind, tenants can safely share relays.

**The wire protocol must be identical between the two** so agents and clients are the same
build — only control-plane config differs.

---

## Cost and capacity planning

These numbers should drive the roadmap, not be discovered later:

- Direct P2P succeeds in roughly **75–80%** of sessions. **20–25% require relay.**
- **15–30% of users are behind symmetric NAT or CGNAT**; mobile carriers nearly always are.
  Symmetric-to-symmetric essentially always relays — STUN cannot predict the port.
- Every relayed byte is received *and* re-sent: **a 3 Mbps stream costs the relay ~6 Mbps**,
  plus ~50–150 ms of added latency.
- Managed TURN wins below ~5M relayed minutes/month; self-hosted coturn on bare metal wins
  above ~50M.

**The relayed fraction is simultaneously your dominant variable cost and your worst
latency.** Investing in NAT traversal to shrink it, and in geographic relay placement to
tame it, pays off twice. Also: race direct and relay connection attempts in parallel and
drop the relay once direct succeeds — it hides hole-punch latency from the user.

---

## Trust posture — the part that decides adoption

For a tool MSPs install as SYSTEM on *their clients'* machines, this section matters more
than the codec.

- **Code signing is mandatory but no longer a silver bullet.** Microsoft removed the
  instant-SmartScreen-reputation that EV certs used to grant (changed around 2024); OV and
  EV are now treated the same and reputation accrues organically with download volume.
  Since June 2023 the private key must live on a FIPS-140 hardware token or cloud HSM — no
  more PFX files. **Azure Trusted Signing** is the pragmatic path if your entity is
  eligible (verify regional availability before budgeting). Sign everything, timestamp
  everything (RFC 3161), and never rotate publisher identity — reputation is per-publisher.
- **Expect AV/EDR friction and manage it.** Your agent does textbook riskware things:
  SYSTEM service spawning processes into user sessions, `SetThreadDesktop` to Winlogon,
  `SendSAS`, input injection, self-update downloading executables. Proactively submit
  binaries to Defender and major AV vendors and enroll in whitelisting programs. Being
  classified as a RAT is an existential risk for this product category.
- **Consent and visibility are product features, not friction.** Attended sessions show a
  clear consent prompt and on-screen indicator; unattended access is policy-gated and
  audit-visible. Note that ScreenConnect *restricted* hiding the connection banner and tray
  icon in 2025 specifically to curb abuse — match that stance deliberately. A remote-access
  tool that can run invisibly is a RAT, and both AV vendors and buyers will treat it as one.
- **Tamper-evident audit:** hash-chained, per-tenant, exportable to SIEM. MSPs need it for
  their own SOC 2 / HIPAA obligations.
- **Supply chain:** SBOM (CycloneDX) per release, pinned dependencies, `cargo audit` /
  `govulncheck` in CI, signed releases with published checksums.
- **Learn from the incumbent's failure:** ScreenConnect was hit by CVE-2024-1708/1709, an
  authentication bypass. Treat auth and update integrity as first-class from the start.

---

## Licensing

DeskRally is fully open source under Apache-2.0. The agent, control plane, console,
self-hosted deployment and multi-tenant functionality share this policy; there is no
proprietary tier.

Dependencies retain their own licenses. coturn (BSD) and Pion (MIT) are permissively
licensed; x264 is GPL, so encoder selection requires a dependency-license review.
Keep a license scanner in CI.
