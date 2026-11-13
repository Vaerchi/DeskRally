# Build and deployment technical reference

How to build the whole platform into a `dist/` and deploy it: the backend (three servers +
Postgres), the Windows agent, and the browser viewer. Start with the
[Docker installation guide](guides/server-deployment.md) or [native installation guide](guides/native-server.md).
Use the [configuration reference](guides/server-configuration.md) for service settings and
the [backup runbook](22-backup-and-restore.md) for recovery.

The platform has four shippable pieces:

| Piece | What it is | Where it runs |
|---|---|---|
| **Agent** | `agent_host.exe` (+ `stream_probe.exe`) — LocalSystem Windows service that streams the desktop over WebRTC, injects input, serves backstage tooling | each managed Windows machine |
| **Signaling** | `signaling.exe` — WebSocket rendezvous (registration, SDP/candidate brokering), `:8080` | backend host |
| **Relay** | `relay.exe` — E2E-blind byte forwarder, TCP `:9000` / WS `:9001` | backend host |
| **Control-plane** | `controlplane.exe` — multi-tenant API (auth, RBAC, grant minting, audit), `:8081`, needs Postgres | backend host |
| **Viewer** | static React/TS bundle | any static web host |

---

## 1. Prerequisites

**To build** (on a Windows dev box):
- Rust (cargo ≥ 1.97) with the MSVC toolchain
- Go satisfying each checked-in go.mod; the toolchain version is part of the release
- Node satisfying web/viewer/package.json engines (Node 24 is a compatible build target)
- PowerShell 5.1+ or PowerShell 7 (`pwsh`)
- **libvpx, via vcpkg — see [1a](#1a-native-build-prerequisite-libvpx-vp8) below.** This is a *new*
  prerequisite as of the H.264 → VP8 migration and `cargo build` will NOT work without it.

### 1a. Native build prerequisite: libvpx (VP8)

The WebRTC video media track is encoded with **VP8** via libvpx (`crates/transport-webrtc/src/video/vp8.rs`).
Unlike the OpenH264 crate it replaced, libvpx is **not vendored** — the `env-libvpx-sys` crate binds
to a libvpx you install yourself. Install it once per build machine (and in CI):

```powershell
# one-time: get vcpkg (skip if you already have it)
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat

# the actual prerequisites
C:\vcpkg\vcpkg install libvpx:x64-windows-static
C:\vcpkg\vcpkg install opus:x64-windows-static
```

**libopus** is the second one, and it is here for the same reasons libvpx is: the WebRTC AUDIO track
is Opus (`crates/transport-webrtc/src/audio.rs`), Opus is mandatory-to-implement in WebRTC so every
browser decodes it, and it is royalty-free with an explicit patent grant — the property that decided
VP8 over H.264. It is also not vendored, and there is no `-sys` crate in the way: that module
declares the five libopus functions it uses directly, so `crates/transport-webrtc/build.rs` needs
only the search path (`OPUS_LIB_DIR`, defaulted in `.cargo/config.toml`).

**The triplet MUST be `x64-windows-static`.** That triplet builds libvpx against the *static* CRT
(`/MT`, i.e. `LIBCMT`). The agent binaries are linked with `RUSTFLAGS="-C target-feature=+crt-static"`
so a bare Windows box with no `vcruntime140.dll` can run them (see the agent prerequisite below).
A `x64-windows` (default) or `x64-windows-md` libvpx is `/MD` and the link fails with:

```
LNK2038: mismatch detected for 'RuntimeLibrary': value 'MD_DynamicRelease' doesn't match value 'MT_StaticRelease'
```

Verify what you got with `dumpbin /directives C:\vcpkg\installed\x64-windows-static\lib\vpx.lib | findstr DEFAULTLIB`
— it must say `/DEFAULTLIB:LIBCMT`, not `MSVCRT`. The same check applies to `opus.lib`.

Note the LIBRARY NAMES the linker is asked for: vcpkg's static triplet produces `vpx.lib` and
`opus.lib`, not `libvpx.lib` / `libopus.lib`. Asking for the `lib`-prefixed name fails with LNK1181,
which is why `VPX_STATIC` is deliberately left unset and why `build.rs` emits
`rustc-link-lib=static=opus`.

**How the build finds it.** The repo's `.cargo/config.toml` sets `VPX_LIB_DIR`, `VPX_INCLUDE_DIR`
and `VPX_VERSION` in its `[env]` table (cargo applies `[env]` to build scripts), pointing at
`C:/vcpkg/installed/x64-windows-static`. So a plain `cargo build` works with no shell setup. If your
vcpkg lives elsewhere — or you are on Linux with a distro libvpx — export your own `VPX_LIB_DIR` /
`VPX_INCLUDE_DIR`: every entry uses cargo's default `force = false`, so your environment wins.

Two things that will look surprising and are deliberate:

- **`VPX_VERSION = "1.13.0"` while vcpkg installs libvpx 1.16.0.** `env-libvpx-sys` ships
  *pre-generated* bindgen output (which is why clang/bindgen are **not** needed) and 1.13.0 is the
  newest it has. Every struct we touch is field-for-field identical between the 1.13 bindings and
  the 1.16 headers; the one thing that did change is the `VPX_ENCODER_ABI_VERSION` integer, which
  `vp8.rs` resolves against the *linked* library at runtime instead of trusting the constant
  (the unit test `resolves_the_linked_libvpx_encoder_abi` prints what it found). If a future libvpx
  changes an actual struct layout, that test — and encoding — will fail loudly rather than silently
  corrupt.
- **`VPX_STATIC` is deliberately NOT set.** When set, `env-libvpx-sys` emits
  `cargo:rustc-link-lib=static=libvpx` on Windows, i.e. it looks for `libvpx.lib`; vcpkg's static
  triplet produces `vpx.lib`, so the link fails with `LNK1181`. Leaving it unset links `vpx.lib`,
  which under the `x64-windows-static` triplet *is* the static archive (that triplet ships no DLL).

**Non-`+crt-static` builds emit `LNK4098: defaultlib 'LIBCMT' conflicts…`.** That is expected for
plain `cargo test` / `cargo build` (which default to `/MD`) linking the `/MT` `vpx.lib`. It is
harmless here — nothing crosses the CRT heap boundary; libvpx frees only what it allocated, and we
free only what we allocated — and it disappears entirely in the shipping `+crt-static` build.

**Licensing note.** libvpx is BSD-3-Clause **with an explicit patent grant**, which is the whole
point of the migration: the previous OpenH264 path carried MPEG-LA H.264 licensing exposure that
blocked open-sourcing. The binding crate `env-libvpx-sys` is **MPL-2.0** (file-level weak copyleft,
fine to link from an Apache-2.0 project as long as that crate's own files stay MPL — we do not
modify it).

**To run the backend:**
- A host for the three server binaries (Windows or Linux — Go cross-compiles; the shipped
  `dist/servers` are Windows `.exe`)
- PostgreSQL 14+ (16 recommended) for the control-plane
- (WAN only) a coturn TURN server with a public IP

**To run the agent:** a Windows 10/11 (or Server) target, installed **elevated** (the service is
LocalSystem). The agent binaries are built with the **static CRT**, so a bare box with no
`vcruntime140.dll` runs them.

---

## 2. One-command build

Source builds default to auto-update off. Agent builds select the official identity only with
`DESKRALLY_UPDATE_OFFICIAL=1`; the desktop client uses `-OfficialUpdates`. For your own agent
feed, set `DESKRALLY_UPDATE_FEED`, `DESKRALLY_UPDATE_PUBKEY_FILE` and
`DESKRALLY_UPDATE_PUBLISHER` together. See the build kit, `docs/48-windows-build-kit-and-deployment-passes.md`, in the source tree.

From the repo root:

```powershell
pwsh -File scripts/build-release.ps1
```

This produces a top-level `dist/`:

```
dist/
  agent/     agent_host.exe + stream_probe.exe (static CRT), config.template.json, README.md, install-agent.ps1
  servers/   signaling.exe, relay.exe, controlplane.exe, migrations/*.sql
  viewer/    index.html + assets/  (static bundle)
  README.md  MANIFEST.txt
```

The Rust release build compiles webrtc-rs and links libvpx (see [1a](#1a-native-build-prerequisite-libvpx-vp8)
— **install it first or this step fails**) and takes a few minutes; let it run. Fast
iteration switches: `-SkipRust` and `-SkipViewer` reuse existing `dist/` subtrees. The script fails
loudly if any component build fails, and (when the VS `dumpbin` is on PATH) asserts the agent bins
carry no `vcruntime` dependency.

---

## 3. Deploy the backend

### 3a. Native (three servers + Postgres)

**1) Provision Postgres and apply the migrations**

**For current releases, use the migration runner.** The low-level SQL examples and dated migration
notes below explain the schema history; they are not the installation procedure for a database
managed by the checksum ledger. Do not mix manual replay with the supported runner.

```powershell
$env:MIGRATE_DATABASE_URL = Read-Host 'Owner PostgreSQL connection URL'
$env:APP_DB_PASSWORD = Read-Host 'New rmt_app password' -MaskInput
.\dist\servers\controlplane.exe migrate --dir .\dist\servers\migrations
if ($LASTEXITCODE -ne 0) { throw 'Migration failed; do not start the new server' }
Remove-Item Env:MIGRATE_DATABASE_URL, Env:APP_DB_PASSWORD
```

Use PowerShell 7 for the masked prompt. Native Linux archives use bin/controlplane and their
top-level migrations directory instead. The runner applies the release's files in order and records
their checksums in schema_migration. Do not use --baseline without verifying an existing schema.
Migrations use the owner/admin connection; the serving application uses the separate limited
rmt_app connection. See the [complete native procedure](guides/native-server.md#create-the-database-and-apply-migrations).

#### SQL-level migration detail

Apply the migrations **as an admin/owner role** (they create tables, functions, and the app
role), in **name order — every file in the directory**. Do not transcribe a range here; that is the
source of schema drift.

Use `--single-transaction` on every file. Several migrations are multi-statement and are not
individually re-runnable, so a failure part-way through one leaves a half-applied schema that
`psql` still exits 0 from — e.g. `0019` adds a column, backfills it, and only then makes it `NOT
NULL` and unique; stopping between those leaves a nullable column and an export that silently omits
every row with a NULL cursor.

```powershell
# Create a database, then, as an ADMIN/owner role, apply EVERY migration in name order.
# Apply the complete ordered set of migration files.
$conn = "service=deskrally-migrations"  # configure your own libpq service and authentication
Get-ChildItem dist/servers/migrations/*.sql | Sort-Object Name | ForEach-Object {
    Write-Host "applying $($_.Name)"
    psql $conn -v ON_ERROR_STOP=1 --single-transaction -f $_.FullName
    if ($LASTEXITCODE -ne 0) { throw "migration $($_.Name) failed" }
}
```

```bash
# POSIX equivalent. `sort -V` (not plain `sort`) so 0100 would order after 0099, not after 0009.
conn="service=deskrally-migrations"  # configure your own libpq service and authentication
for f in $(ls dist/servers/migrations/*.sql | sort -V); do
    echo "applying $f"
    psql "$conn" -v ON_ERROR_STOP=1 --single-transaction -f "$f" || exit 1
done
```

> Apply every migration in file order. A handwritten list can omit required schema changes.
> The build checks migration numbering for gaps; the runner records checksums.

> **`0023` is additive and safe to apply ahead of the binary swap.** It creates the
> `session_ticket_redemption` table (RLS-isolated like every other) plus `cp_session_ticket_redeem`,
> and touches nothing existing. It backs deployment-wide single-use enforcement for session tickets:
> without it the signaling server falls back to its per-process spent-ticket map and logs that it is
> doing so, which is the deliberate fail-soft posture — see §6 and `server/signaling/ticketredeem.go`.

> **`0020` is additive and safe to apply ahead of the binary swap.** It creates a new table plus
> two `cp_credential_token_*` functions and touches nothing existing, so an older binary keeps
> running unchanged against it — it simply never mounts the three credential-token routes
> (`POST`/`DELETE /users/{id}/password-reset`, `POST /auth/password/redeem`), which is what makes
> first-password provisioning and administrative reset possible. Applying the migration without
> deploying the new binary leaves an unused table; deploying the new binary without the migration
> makes those three routes 500 on their first call.

> **`0019` must be applied BEFORE the new control-plane binary serves traffic**, and the old binary
> keeps working after it: `ingest_seq` is `NOT NULL` with no default, so a *pre*-0019 binary's
> `INSERT` into `backstage_audit_event` fails once the column exists. Apply the migration during the
> same maintenance step that swaps the binary — for a rolling deploy, drain backstage audit ingest
> first, or accept that in-flight forwarders retry (they keep each batch buffered until a 2xx, so
> nothing is lost, but the trail lags until the new binary is live).

> Run migrations in order: later files can replace earlier security functions. Applying an older
> file last can revert those checks.

> **0010 backs agent authentication.** It adds `cp_machine_identity_by_device_id`, the RLS-bypassing
> lookup behind `GET /internal/devices/{device_id}/identity` — how the signaling server learns the
> Ed25519 key pinned for a device so it can verify a `register_agent` proof of possession. Without
> it that route returns 500 and no agent can register against an enforcing signaling server. It must
> be applied AFTER `0008` (which is what makes a device id resolve to exactly one tenant).

> **0011 makes tenant suspension mean something for enrollment.** `cp_enrollment_token_redeem` now
> also requires the token's tenant to be active (`disabled_at IS NULL`), matching
> `cp_resolve_tenant_by_slug`. Before it, a token minted while a tenant was active kept enrolling
> agents into that tenant after it was suspended.

> **0012 makes TOTP codes single-use.** It adds `user_totp.last_step`, the RFC 4226 counter of the
> most recently accepted login code; a code whose step is not strictly greater is rejected
> (RFC 6238 §5.2). Without it, the ±1-step skew window left every code valid for ~90 seconds and an
> observed code could be replayed to log in. The control plane WRITES this column on every TOTP
> login, so applying it is not optional once the binary is upgraded.

> **0018 is on the AUTHENTICATION HOT PATH — apply it before starting the upgraded binary.** It adds
> `user_session.credential_epoch`, which `PgSessionStore` writes on every session insert and reads on
> every request; without the column the control plane starts and then fails **every login and every
> authenticated request**. It closes a real race: a login that read the old password hash could
> insert its session *after* a password change's mass revocation committed, keeping a 12-hour session
> authorized by the password that was just retired. Sessions now carry the credential VERSION they
> were authorized by and are refused when it is older than the credential's current one.
>
> **It signs out everyone currently logged in with a local password, exactly once — plan for that.**
> There is deliberately no backfill. A session created before this column exists cannot be dated:
> we do not know which credential version authorized it, and stamping "the current one" would
> re-authorize precisely the sessions the fix exists to refuse (a session left live by a failed
> revocation, or one created by the race itself). NULL means "unknown" and fails closed. Users with
> no local password (federated) are unaffected. Nothing to roll back — signing in again is the
> remedy — but announce it or apply it in a maintenance window, like any forced-logout change.

> **0008 is a security constraint.** It makes `machine.device_id` globally unique, so a device id
> belongs to exactly one tenant and no tenant can mint a session ticket naming another tenant's
> agent. On an existing database it fails if two tenants already share a device id — that collision
> IS the exposure; re-enroll one side rather than skipping the migration. Find them with
> `SELECT device_id, count(*) FROM machine GROUP BY device_id HAVING count(*) > 1;`

> **Roles (docs/67, migration 0076):** three roles matter. The migration role (superuser, owns the
> tables), `rmt_app` (the application: DML only, RLS-subject) and `rmt_definer` (NOLOGIN, BYPASSRLS,
> owns every `SECURITY DEFINER` function, owns no table, a fixed list of table privileges). Nothing
> connects as `rmt_definer`; a defect in a definer function yields cross-tenant reads/writes of those
> tables, not a superuser. **Before applying 0076, rehearse it on a restored database backup** (the
> migration role must be a superuser or the migration stops before changing anything), then run the
> full pg suite or the application smoke against the rehearsal. Rollback: for each routine
> `ALTER ROUTINE public.<fn>(<args>) OWNER TO <migration role>;`, then
> `REASSIGN OWNED BY rmt_definer TO <migration role>; DROP OWNED BY rmt_definer; DROP ROLE rmt_definer;`
> and delete the 0076 row from `schema_migration` so it is not considered applied. Roles are cluster-wide but
> `REASSIGN OWNED` / `DROP OWNED` act on ONE database: run them in EVERY database of the cluster, rehearsal
> copies included (or drop the rehearsal database first, or rehearse in a separate cluster), or `DROP ROLE`
> fails while any database still holds grants or owned objects for the role. PostgreSQL 14 note: 0076 revokes
> CREATE on schema `public` from PUBLIC so `rmt_definer` cannot create objects there. Cosmetic: 0076's
> `REVOKE ALL` turns a NULL (default) ACL into an explicit owner-only ACL on tables it touches (seen on
> `platform_config`, `platform_operator`, `schema_migration`); the privileges are identical, so an ACL diff
> across the migration shows these rows without any change in access, and the rollback need not undo them.

> **RLS note — the application MUST connect as `rmt_app`, NOT as the admin/owner:** the schema uses
> Row-Level Security as the multi-tenant isolation guarantee, and PostgreSQL **bypasses RLS for a
> superuser or a table owner** (a superuser is exempt even with `FORCE ROW LEVEL SECURITY`). If the
> app connects as `postgres`/the owner, **RLS silently does nothing and tenants are not isolated.**
> `0005_app_role.sql` provisions `rmt_app` — a least-privilege, non-superuser, non-owner,
> **non-BYPASSRLS** login role that RLS genuinely applies to — and grants it exactly the DML it
> needs. Set `DATABASE_URL` to connect as **`rmt_app`** (see the run step below). Provision its
> password out-of-band (the migration does not hardcode one); e.g. `ALTER ROLE rmt_app PASSWORD
> '…';` as the admin role, or rely on your `pg_hba.conf` auth. The `rls_test.go` integration test
> proves the isolation: as `rmt_app` a query pinned to tenant A sees only A's rows and cross-tenant
> writes are blocked by the policy, while the same query as a superuser sees every tenant.

#### Run the server processes

The abbreviated shell transcript below documents binary flags, not a complete service environment.
Use the [per-service configuration reference](guides/server-configuration.md#service-to-service-credentials)
and the [native launchers](guides/native-server.md#start-the-services-in-the-foreground) for a full
installation. Start the control plane first, copy its public grant key, then start signaling with
matching device-identity credentials. Keep internal listeners on loopback behind the proxy.

```powershell
# control-plane — production (Postgres) mode.
# DATABASE_URL MUST connect as the least-privilege rmt_app role (RLS-subject), NOT postgres/owner:
$env:DATABASE_URL = "<your rmt_app database connection URL>"
$env:GRANT_ISSUER_SEED = "<64 hex chars>"   # openssl rand -hex 32 — KEEP STABLE across restarts
$env:CP_SECURE_COOKIE  = "1"                # when served over HTTPS
$env:CP_LISTEN = "127.0.0.1:8081"
$env:CP_DEVICE_IDENTITY_TOKEN = "<same random secret configured on signaling>"
$env:TOTP_ENCRYPTION_KEY = "<separate stable 64-hex encryption key>"
$env:CP_SIGNALING_URL = "wss://remote.example.com/ws"
dist/servers/controlplane.exe
```

Keep it running. Copy grant_issuer_pubkey from its startup log into a second terminal's signaling
environment. This is the public key, not the private seed. An anonymous /grant/pubkey request is
refused; an authenticated console session or API token can read it after bootstrap.

```powershell
$env:SIGNALING_TICKET_PUBKEY = "<64-hex public key from control-plane startup>"
$env:SIGNALING_DEVICE_IDENTITY_URL = "http://127.0.0.1:8081"
$env:SIGNALING_DEVICE_IDENTITY_TOKEN = "<same random CP_DEVICE_IDENTITY_TOKEN>"
$env:SIGNALING_ALLOWED_ORIGINS = "https://remote.example.com"
dist/servers/signaling.exe -addr 127.0.0.1:8080 -relay 127.0.0.1:9000
```

If you need the private raw relay, run it in a third terminal. It does not replace TURN for browsers.

```powershell
dist/servers/relay.exe -tcp 127.0.0.1:9000 -ws 127.0.0.1:9001
```

Control-plane environment variables:

| Var | Meaning |
|---|---|
| `CP_LISTEN` | listen address (default `:8081`) |
| `DATABASE_URL` | Postgres DSN — **must connect as the `rmt_app` least-privilege role** (RLS-subject), never `postgres`/owner (they bypass RLS). **Unset ⇒ production startup refuses to serve.** Development mode requires the separate explicit CP_INSECURE_DEV flag and is not a deployment mode. |
| `GRANT_ISSUER_SEED` | 32-byte Ed25519 seed, hex (64 chars). Keeps `grant_issuer_pubkey` **stable across restarts**. Unset ⇒ ephemeral key regenerated each boot (agents pinned to the old key reject grants) |
| `CP_ISSUER_NAME` | name used in TOTP provisioning URIs (default `rmt-control-plane`) |
| `AGENT_PUBLISHED_VERSION` | operator-designated expected agent build, `<semver>+<short-sha>`; `GET /agent-version` returns it and the console flags outdated machines. Empty = tracking off (docker compose forwards it) |
| `CP_MAX_CONNS` / `CP_READ_TIMEOUT` | concurrent-connection cap (positive integer) and whole-request read timeout (Go duration, e.g. `60s`); empty = built-in defaults (docker compose forwards both) |
| `CP_AUTH_LOOKUP_CONCURRENCY` / `CP_AUTH_LOOKUP_QUEUE` | cap on concurrent database lookups of credentials that have not yet proved themselves (anonymous garbage cookies / bearer tokens, logout) and how many more may wait up to 500 ms before a 503; empty = a quarter of the pool (`pool_max_conns`, default 16, so 4) and twice that waiting. Separately, each source address gets 60 FAILED lookups per minute (IPv6 per /64) and then a 429 with no database call; a token that validated in the last 10 minutes is never refused by either, and database faults are never charged as failures (credential_guard.go, docs/26). Concurrent first lookups of one token share a slot. After a restart every session is briefly unproven, so a first request can get 429/503 under attack; the first exhaustion of a source's budget is logged once per minute (a log line naming a reverse-proxy address means `CP_TRUSTED_PROXIES` is not set). Docker compose forwards both |
| `CP_PASSWORD_HASH_CONCURRENCY` / `CP_PASSWORD_HASH_QUEUE` | argon2 concurrency (~64 MiB per slot) and waiting-queue bound (docs/25 F01); empty = defaults (docker compose forwards both) |
| `DIRECTIVE_SIGNING_SEED` / `CP_SIGNALING_NOTIFY_URL` | fleet directives (docs/65): the dedicated signing seed (never the `GRANT_ISSUER_SEED`) and signaling's base URL for pending-directive notifications (docker compose defaults it to `http://signaling:8080`). Empty seed = directive routes not mounted |
| `CP_SECURE_COOKIE` | `1`/`true` marks the session cookie Secure — set behind HTTPS |
| `CP_SIGNALING_URL` | signaling WS endpoint returned by `POST /sessions` alongside the signed session ticket, e.g. `wss://signal.example/ws` (default `ws://127.0.0.1:8080/ws`) |
| `CP_DEVICE_IDENTITY_TOKEN` | shared secret (**32+ chars**, e.g. `openssl rand -hex 32`) the signaling server presents as `Authorization: Bearer …` on `GET /internal/devices/{device_id}/identity`. Must equal the signaling server's `SIGNALING_DEVICE_IDENTITY_TOKEN`. **Unset ⇒ the route is not mounted** (404) and signaling cannot authenticate `register_agent`; a value shorter than 32 characters is refused at startup |
| `CP_PRESENCE_URL` | signaling's presence feed, e.g. `http://signal.internal:8080/internal/presence` — the source of the access panel's online/offline status |
| `CP_PRESENCE_TOKEN` | shared secret (**32+ chars**) presented to that feed; must equal the signaling server's `SIGNALING_PRESENCE_TOKEN`. **Unset/too short ⇒ not fatal:** `GET /machines` returns `"presence_known": false` and omits per-machine `online`, and the console shows "status unavailable". Nothing is authorized on presence, so it fails SOFT by design |

Signaling environment variables for presence:

| Var | Meaning |
|---|---|
| `SIGNALING_PRESENCE_TOKEN` | shared secret (**32+ chars**) that gates `GET /internal/presence`. **Unset or shorter than 32 chars ⇒ the route is NOT mounted** — there is no unauthenticated mode, because the registry is cross-tenant and an open feed is a fleet-enumeration oracle. Must equal the control plane's `CP_PRESENCE_TOKEN` |

Presence (docs/01 §4, migration `0017`) is read live from signaling's agent registry rather than
inferred from an agent heartbeat: an agent is online exactly when the broker could reach it. The
feed returns **device ids, freshness, and the agent-asserted `os` description** (bounded at 255
bytes on receipt) — no pubkey, tenant or NAT type — and the control plane intersects it with the
caller's own RLS-scoped machines, so a shared signaling server can never leak one tenant's fleet
to another. Each read also stamps `machine.last_seen`, which is what makes "offline since 14:32"
answerable after the agent disconnects and after signaling restarts — and refreshes `machine.os`
where the announced value differs from the stored one, so the inventory column tracks OS upgrades
instead of freezing at enrollment.
**Scope limit:** the registry is per-instance and in-memory, so a multi-instance signaling fleet
reports only the agents connected to the instance being polled until the shared presence store
(docs/02 "Deployment topologies") exists.

The device-identity route (M3, `docs/11-agent-identity-contract.md`) deliberately sits OUTSIDE the
auth → tenant (RLS) chain: the lookup is cross-tenant, and the signaling server is not a tenant
principal. It is therefore gated on the service token alone — treat that token like a database
password, keep the endpoint off the public internet if your topology allows it, and rotate it on
both processes together. It returns only `{device_id, tenant_id, pubkey}`, answers 404 identically
for an unknown device and for one with no pinned key, and is rate-limited per source IP. It is
deliberately **not** written to the management audit trail: it fires on every agent reconnect and
would drown the trail of human actions.

Session brokering (M2): `POST /sessions` returns `signaling: {url, device_id, session_id, ticket}`;
the viewer dials that URL and presents the 2-minute Ed25519-signed ticket in `connect_request`,
which the signaling server verifies against `SIGNALING_TICKET_PUBKEY` before pairing peers.

Health checks: `GET /healthz` on `:8080` (signaling) and `:8081` (control-plane); the relay has no
HTTP health endpoint (check the `:9000` TCP socket).

> **TLS:** none of the servers terminate TLS themselves. Front them with a reverse proxy (nginx,
> Caddy, a cloud LB) for `wss://` signaling and `https://` control-plane in production.

#### 3a-i. Self-signed TLS for an own-machines deployment

For a LAN/VPN deployment on machines you control, a public CA is unnecessary — but **self-signed
only works if you issue ONE local CA and TRUST it machine-wide**. `scripts/make-local-ca.ps1`
does that:

```powershell
.\scripts\make-local-ca.ps1 -Names rmt.lan,192.0.2.50 -InstallCa   # elevated
# then on every OTHER agent/browser machine, elevated:
Import-Certificate -FilePath .\rmt-local-ca.crt -CertStoreLocation Cert:\LocalMachine\Root
```

Three failure modes it exists to prevent — each one presents as an unexplained connection refusal:

1. **`wss://` gives no interstitial.** A browser lets you click through an untrusted certificate for
   an `https://` page load, but a WebSocket handshake to an untrusted certificate is simply refused,
   with only a generic console error. Accepting the viewer's own certificate warning does **not**
   make signaling work. Trusting the CA is the only fix.
2. **The agent never disables certificate validation** (`enroll.rs`) and runs as **SYSTEM**, so the
   CA must land in `LocalMachine\Root` — a per-user import does nothing for the service.
3. **Chrome ignores Subject CN and matches only SANs**, and an IP address must be an *IP* SAN (a DNS
   SAN spelled `192.0.2.10` does not match). Pass every name/IP the deployment is reached by to
   `-Names`; a name outside the SAN list is refused.

Keep `rmt-server.pfx` and the CA private key off shared storage: whoever holds the CA key can
impersonate the control plane to every agent that trusts it.

> **This is transport TLS only — it does NOT code-sign the agent binaries.** Unsigned binaries that
> install a SYSTEM service, capture the screen and inject input can still be blocked by endpoint
> protection. Use your organization's code-signing and software-distribution policy. Transport
> certificate trust does not establish an executable's publisher identity; investigate a block
> instead of treating a trusted transport certificate as permission to bypass it.

#### 3a-ii. Client source address (audit trail) and the proxy-trust settings

The control plane records the client address of every request that writes an audit event
(`audit_event.source_ip`), of every login (`user_session.source_ip` / `user_agent`, password and SSO
alike) and of every remote session (`session_record.source_ip`). `GET /audit`, the audit export and
the console's **Audit** tab show it as `source_ip` / the **Source IP** column (also the last column of
the console's "Export CSV"); it is blank for an event written outside a request (a background job).
It is plain text, IPv4 or IPv6. With `CP_TRUSTED_PROXIES` (or neither setting) it is never taken from a
header an untrusted peer chose; the legacy `CP_TRUST_PROXY_IP=1` mode is the exception, below.

Which address is recorded is the SAME derivation the admin/tenant IP allow-lists use:

* **`CP_TRUSTED_PROXIES`** (a CIDR list; the recommended mode): the TCP peer's address, unless the peer is
  inside the list, in which case the rightmost `X-Forwarded-For` hop. A request from any other peer has its
  header ignored, so a client cannot choose what is recorded.
* **`CP_TRUST_PROXY_IP=1`** (legacy, single reverse proxy): the rightmost `X-Forwarded-For` hop **from any
  peer**. Anything that can reach the control-plane port without going through the proxy can write any
  address into the audit trail (and past the IP allow-lists, which have the same weakness in this mode).
  Use it only where the proxy is the sole path to the port, and prefer `CP_TRUSTED_PROXIES`.
* Neither set: the TCP peer's address (behind a proxy that is the proxy's own address).

### 3b. Docker alternative (authored, UNVERIFIED here)

> Docker is **not installed** on the build machine, so `deploy/docker-compose.yml` and the three
> `Dockerfile`s were authored and source-checked but **not built or run** in this environment.
> Treat the images as unverified until built in CI.

```bash
# from repo root
docker compose -f deploy/docker-compose.yml up --build
```

Brings up **signaling** (:8080), **relay** (:9000/:9001), **control-plane** (:8081), and
**Postgres** with the migrations auto-applied on first init (they are mounted into
`/docker-entrypoint-initdb.d`, which Postgres runs only against an empty data volume). Override
secrets via a `.env` file next to the compose file — at minimum `POSTGRES_PASSWORD` and
`GRANT_ISSUER_SEED`. A **coturn** service is included commented-out (see §6). The viewer is not
containerized — host it separately (§5).

---

## 4. Deploy the agent (per Windows machine)

**1) Get the control-plane's grant issuer public key** (for secure-mode backstage):

> **An anonymous `curl http://CONTROLPLANE_HOST:8081/grant/pubkey` does NOT work.** It answers
> `{"error":"unauthorized"}`. `GET /grant/pubkey` is registered on the **protected** router
> (`control-plane/http.go`), behind the same ipAllow → CSRF → auth → tenant chain as every
> other console API route. It is a console API route, and console API requires a credential.
>
> The **value** is not a secret — it is a public key, it authorizes nothing on its own, and the
> control plane hands the identical hex string to an *unauthenticated* attended guest in the
> `POST /attended-sessions/redeem` response (docs/12), because a guest has no config file and
> redeem is the only channel that can tell it which issuer to trust. The route is gated because
> of what it *is*, not because the key is confidential. Knowing that is what tells you the 401
> is normal rather than a misconfiguration worth debugging.

Four sources actually return it. Which one you want depends on whether a script or a human is
asking, and whether the deployment has been logged into yet.

**a) An API token — the source that scripts.** `handleGrantPubkey` checks **no capability**: it
only has to clear the protected mux's authenticator, and `APITokenAuthenticator`
(`control-plane/apitoken_auth.go`) resolves an `Authorization: Bearer rmt_api_…` header ahead of
the cookie path. So a fleet installer can fetch the key headlessly:

```bash
# behind the Caddy front, which serves the control plane under /cp (deploy/Caddyfile)
curl -sH "Authorization: Bearer $RMT_API_TOKEN" https://console.example.com/cp/grant/pubkey
# or straight at the control plane, no proxy in front
curl -sH "Authorization: Bearer $RMT_API_TOKEN" http://CONTROLPLANE_HOST:8081/grant/pubkey
# {"grant_issuer_pubkey":"<64 hex chars>"}
```

Mint the token **once** in the console (`POST /api-tokens`, gated on `CapManageTenant` — Owner
only) and scope it as small as it goes: `["view_machines"]`. A token must carry at least one
capability from the closed grantable set (`view_machines`, `manage_machines`, `manage_groups`,
`view_sessions`, `view_audit`), but this route reads none of them, so the smallest one is
enough — do not hand a build agent `manage_machines` just to read a public key. The plaintext
is shown ONCE and is a bearer secret: treat it like a password.

> **Both IP allow-lists still apply**, ahead of the token. `CP_ADMIN_IP_ALLOWLIST` and the
> per-tenant list wrap the whole protected chain, so a build agent off the list is refused
> holding a perfectly valid token. CSRF is not in the way (safe methods pass, and a Bearer
> request is exempt regardless — an `Authorization` header is not ambient authority a foreign
> page could attach).

**b) The startup log — the source on a box nobody has logged into yet.** The control plane
prints the key on every boot, right before it starts listening
(`control-plane/cmd/controlplane/main.go`). On a brand-new deployment this is the *only* source:
signaling needs the value before anyone can log in to mint a token, which is why docs/20 §4
harvests it this way.

```
control-plane-1  | control-plane: grant_issuer_pubkey=<64 hex chars>
```

The `control-plane-1  | ` prefix is docker compose's, not the app's; under systemd you see the
bare `control-plane: grant_issuer_pubkey=…` line.

```bash
docker compose -f deploy/docker-compose.yml logs controlplane | grep grant_issuer_pubkey
journalctl -u controlplane | grep grant_issuer_pubkey    # systemd rather than compose
```

Give it a moment. The container reports "up" well before that line appears (~26 s on the first
real deployment, migrations included), and grepping too early returns nothing — which reads
exactly like "the key was never generated". docs/20 §4 has the wait-then-grep loop.

**c) A logged-in console.** That is what the protected route is *for*: the browser session that
already exists fetches the key so an operator can copy it into an install command.

**d) The attended redeem response.** `POST /attended-sessions/redeem` returns the same value to
an unauthenticated guest (docs/12). Useful as a cross-check that the issuer a live deployment is
actually using matches the hex you are about to provision.

> **Whatever the source, the value only stays valid if `GRANT_ISSUER_SEED` is set** (§2).
> Without it the control plane generates a fresh issuer key on every boot and logs a warning
> saying so; the hex you provisioned into `config.json` then stops matching, and every grant is
> rejected after the next restart. Set the seed *before* you harvest the key, not after.

> **Never paste a real key from another deployment into a doc, script or template.** It is the
> public half, so it leaks nothing — but a key copied into a deployment it does not belong to
> fails as *backstage silently denied everywhere*, which looks like a broken agent rather than a
> wrong constant.

**2) Mint an enrollment token** (console → Machines → Enroll, or `POST /enrollment-tokens` with the
`manage_enrollment` capability). It is a **single-use bearer secret**: treat it like a password, and
mint one per machine or per batch rather than reusing one indefinitely.

**3) Copy `dist/agent/` to the target and install (elevated / Administrator):**

```powershell
./install-agent.ps1 -SignalingUrl "ws://SIGNALING_HOST:8080/ws" `
                    -ControlPlaneUrl "https://CONTROLPLANE_HOST:8443" `
                    -EnrollmentToken "<token from step 2>" `
                    -GrantIssuerPubkey "<64 hex chars from step 1>" `
                    -Stun @("stun:stun.l.google.com:19302")
```

`install-agent.ps1` copies the binaries to `C:\rmt-agent-bin`, writes `C:\rmt-agent\config.json`,
runs `agent_host enroll` (see below), then runs `agent_host install` to register + start the
LocalSystem service. The service's per-session SYSTEM helper connects to signaling and streams once
a controller pairs with it.

### 4a. Enrollment and agent identity (M3)

`agent_host.exe enroll --control-plane-url <https-url> --token <token> [--name <machine-name>]`
does three things, in this order:

1. loads `C:\rmt-agent\identity.key` (the agent's long-term Ed25519 **seed**, 64 hex chars) or
   generates one, writes it, and tightens its ACL to `SYSTEM` + `Administrators` via `icacls`;
2. `POST <url>/enroll/redeem` with `{token, pubkey, name}` — **never** a `device_id`;
3. writes the **server-minted** `device_id` + `tenant_id` into `config.json` and **clears
   `enrollment_token`** (a spent single-use secret must not linger on disk).

The agent then proves possession of that key on every `register_agent`: signaling issues a random
nonce, the agent signs the `RMTAGENTAUTHv1` preimage
(`crates/protocol/src/agent_auth.rs`), and only a valid signature against the pinned
`machine.pubkey` puts the connection in the registry. See
`docs/11-agent-identity-contract.md`.

Operational consequences:

- **Do not clone a machine image that already contains `identity.key` + a `device_id`.** Both clones
  would claim the same identity and displace each other. Image *before* enrollment: leave
  `device_id` blank and `enrollment_token` set, and the helper enrolls on first boot.
- **`identity.key` is the machine's credential.** Losing it means re-enrolling; leaking it means
  someone else can impersonate the machine. Revoke by clearing/deleting the `machine` row in the
  control plane — the pinned pubkey is the single source of truth, so revocation is immediate.
- Enrollment is attempted **once per helper start**, never in a retry loop: each attempt consumes a
  use of the token.
- Re-running `enroll` on an already-enrolled machine is a no-op (it prints the existing device id and
  exits 0).

`config.json` fields (`crates/agent-windows/src/config.rs`):

| Field | Meaning |
|---|---|
| `signaling_url` | WebSocket rendezvous, e.g. `ws://host:8080/ws` (**required** for streaming) |
| `control_plane_url` | control-plane base URL for enrollment. Set ⇒ **control-plane managed**: the device id is minted server-side and `register_agent` is authenticated |
| `enrollment_token` | single-use enrollment secret; **cleared automatically** after redemption |
| `device_id` | stable per-machine UUID. **Leave blank** — minted by the control plane at enrollment. Only an unmanaged (no `control_plane_url`) agent generates one locally |
| `tenant_id` | written by enrollment; bound into the registration signature |
| `identity_path` | override for `C:\rmt-agent\identity.key` (testing) |
| `stun` | STUN URLs for WAN NAT traversal; empty = LAN/loopback |
| `transfer_dir` | file-transfer root (default `C:\rmt-agent\transfers`) |
| `grant_issuer_pubkey` | control-plane Ed25519 pubkey (hex) — see security note below |

> **`C:\rmt-agent\recordings` is NOT a config field, deliberately.** Session recordings go
> there on the installed agent and nowhere else; there is no override. The recorder owns that
> directory — it sets its DACL (`icacls /inheritance:r`, SYSTEM + Administrators, `(OI)(CI)`), it
> sweeps expired recordings out of it at helper start and session start, and it refuses to start
> below 2 GiB free. An operator-supplied path invites `C:\` or a UNC share, on which
> `/inheritance:r` is either a catastrophe or a no-op, so the knob waits for the validation that
> would make it safe. Sizing: **up to 1 GiB per recording, kept 72 hours.** It is under `CONFIG_DIR`,
> so `agent_host uninstall` and the remote "remove client" self-uninstall (`rmdir /s /q
> C:\rmt-agent`) both take the recordings with them. The **attended** client never records — it
> self-deletes and never runs again, so nothing would ever sweep what it left behind.

> **TLS is mandatory for `control_plane_url`.** `https://` only; plaintext `http://` is accepted for
> `localhost`/`127.0.0.1`/`[::1]` (development) with a warning, and rejected outright for any other
> host — the enrollment token is a bearer secret. Certificate validation is never disabled.

> **Security mode (important):** when `grant_issuer_pubkey` is set, the agent runs in **secure
> mode** — backstage tooling (shell, registry, process control, etc.) is denied until a valid grant
> **signed by that key** is installed for the session. When it is **blank or malformed, backstage is
> DISABLED** for the agent: there is no key to verify a grant against, so every backstage request is
> refused. Screen sharing, input, file transfer and clipboard are unaffected, so the machine stays
> reachable and the setting can be corrected remotely.
>
> The developer CLI `agent_host stream` without `--grant-issuer` can self-issue grants;
> use the installed service with a configured issuer in production.
>
> **Set `grant_issuer_pubkey` in production** — it is the value the control plane logs at
> startup as `control-plane: grant_issuer_pubkey=…`, and the value `GET /grant/pubkey` returns
> to a console session or an API token. An *anonymous* `curl` gets `{"error":"unauthorized"}`;
> §4 step 1 lists the four sources that do work.

> **Unmanaged (LAN/dev) installs.** Omitting `-ControlPlaneUrl` keeps the pre-M3 behaviour: the agent
> invents a local device id and registers with a placeholder pubkey. A signaling server started
> **without** `-insecure-no-agent-auth` will not register such an agent. The installer warns.

**Registry footprint** (for anyone auditing what the installer touches): besides the service itself,
`agent_host.exe install` writes `HKLM\Software\Classes\rmt` — the `rmt://` URL-protocol handler used
by the guest launch link on the `/join` page — pointing at `"<exe>" uri "%1"`. `uninstall` deletes
that subtree. Registration is best-effort: if it fails, the install still succeeds and logs the
failure, because the service is the product and the scheme is only an accelerator. The agent also
sets the `SoftwareSASGeneration` Services policy value (needed for Ctrl+Alt+Del — see §4).

Uninstall: `agent_host.exe uninstall` (as admin). To update binaries, uninstall first — a running
helper holds the exe open.

**Manual streaming without the service** (testing): `agent_host.exe stream --signaling
ws://host:8080/ws [--stun stun:host:3478] [--fps 30]`. Add `--identity C:\rmt-agent\identity.key
--tenant <tenant-uuid>` to register against an **enforcing** signaling server.

---

## 5. Host the viewer

`dist/viewer/` is a static bundle (`index.html` + `join.html` + `assets/`). Serve it from any static
host — nginx, Caddy, S3/CloudFront, GitHub Pages, `python -m http.server`, etc. Serve it over
**HTTPS** in production: browser WebRTC + clipboard APIs require a secure context, and `wss://`
signaling requires the page origin be secure. Point the viewer at your signaling/control-plane
endpoints (configured in the viewer's runtime config / build-time env as applicable).

> The guest landing page must resolve at `/join`, the path returned as `join_url`. Configure an
> SPA fallback on your static host, or use `/join.html`. `build-release.ps1` ships `join.html` as
> a byte-identical copy of `index.html`; keep it even when a fallback is configured.

### 5a. Generating the downloadable guest stub

> **SUPERSEDED for first contact by the typed-code client (docs/27, docs/28).** The first-contact
> download is now ONE static, per-DEPLOYMENT artifact — `DeskRallySupport.exe`, with the
> control-plane origin baked at build time — that the customer runs and TYPES the session code into.
> There is no per-download patch/re-sign step: it is built and signed once per deployment
> (`scripts/build-release.ps1 -ControlPlaneUrl <base> -ProbeControlPlane -Sign …`, where `<base>` is
> the control-plane base the proxy serves: `https://<host>/cp` for the Compose/Caddy layout, never the bare
> origin; see docs/20 section on publishing) and published once
> (`scripts/publish-support-client.ps1`), served from `/download/` (deploy/Caddyfile). The
> per-download-stub recipe below still describes the `make-stub` mechanism used for the pre-configured
> `rmt://`-link stub, but it is NOT how the first-contact download works — read docs/27 first.

The `/join` page can offer a **one-time client download** for a machine that has never installed the
agent (the URI-scheme link only works on a machine that already has). The per-download STUB variant
below is a copy of `agent_host.exe` with the session's attend link patched into it, then re-signed.
Mechanism and security rationale: **docs/12 §13**.

Per attended session, the server side does three things:

```powershell
# 1. Build the attend URI (the SAME string the console's /join link uses):
#    rmt-<fingerprint>://attend?code=<CODE>&cp=<https control-plane URL>[&reason=<text>]
#    (fingerprint = FNV-1a-64 of the control-plane origin — web/viewer attend_link.ts, uri.rs).
# 2. Patch it into a fresh copy of the shipped agent (the running exe IS the template):
agent_host.exe make-stub --uri-file uri.txt --out ScreenShareClient.exe
#    (--uri-file keeps the one-time code off the process command line; --uri also works.)
# 3. RE-SIGN the output — patching invalidates any signature — with the operator's cert:
pwsh -File scripts/sign-release.ps1 -Path <dir containing ScreenShareClient.exe>
```

Then serve `ScreenShareClient.exe` as the `/join` download. When the guest runs it (no arguments),
it reads its own binary, recovers the attend link, and runs the attended flow with a consent prompt —
identical to clicking the `rmt://` link, but with no handler needed first.

> **Not wired into the control plane here.** Steps 1–3 are the integration a production control plane
> performs when serving the download; this repo ships `make-stub` (the piece it calls) but not the
> HTTP handler that orchestrates it, because that handler needs the operator's signing key and a
> template present at deploy time. **Mark-of-the-Web / SmartScreen cannot be validated in a
> `Copy-VMFile`/SMB lab at all** — a per-download-unique binary keeps its *publisher's* reputation
> (reputation is publisher-based, not per-file-hash), but the only way to confirm the browser-download
> experience is a browser download from a real host. Do not assume the prompt behaviour; test it.

---

## 6. Enabling TURN for WAN

The Go relay is a byte-splicer, **not** a TURN server. LAN/loopback works with host candidates
only; STUN handles most home/office NATs; **symmetric NAT — and any network that blocks UDP between
the peers — needs TURN.**

The application-layer relay is separate from TURN and cannot supply ICE credentials.

**How it works now.** The signaling server issues each session's ICE servers in an `ice_servers`
message sent **before** `brokered` — both peers apply it before ICE gathering begins. TURN
credentials are derived per session from a secret held only by the server (coturn's
`use-auth-secret` mode), so **no TURN password is ever stored on an agent** and a stolen credential
expires on its own.

### Configure the signaling server

```bash
SIGNALING_STUN_URLS="stun:turn.example.com:3478"
# Include BOTH transports. The TCP entry is what saves you on a network that blocks outbound UDP —
# often the very reason TURN is needed.
SIGNALING_TURN_URLS="turn:turn.example.com:3478?transport=udp,turn:turn.example.com:3478?transport=tcp"
SIGNALING_TURN_SECRET="$(openssl rand -hex 32)"   # must equal coturn's --static-auth-secret
SIGNALING_TURN_TTL="2h"                           # credential lifetime (default 2h)
SIGNALING_TURN_MAX_PER_USER="20"                  # outstanding credentials per technician (default 20)
SIGNALING_TURN_MAX_PER_TENANT="80"                # outstanding credentials per tenant (default 80)
```

With Docker compose, set these as `TURN_TTL`, `TURN_MAX_PER_USER` and `TURN_MAX_PER_TENANT` in
`deploy/.env`; `deploy/docker-compose.yml` passes them through.

**Size the caps with the TTL.** A credential stays reserved against both caps until it *expires*.
Ending the session does not release it, because otherwise start / collect / end / repeat would mint
unlimited valid usernames. A session over either cap brokers STUN-only (`relay_notice`), and if it
needed the relay it fails. Choose caps for your expected reconnect rate and concurrent users;
the defaults are a 2-hour TTL, 20 credentials per user and 80 per tenant.

**A short TTL does not cut long sessions.** coturn checks the credential's timestamp only when a
NEW client session authenticates (a new 5-tuple, or a new TCP/TLS connection). Refresh,
CreatePermission and ChannelBind on an established allocation keep working after the credential
expires, including after a 438 stale-nonce renewal. A NEW Allocate with an expired credential gets
401, and the viewer's
recovery brokers a fresh session with fresh credentials.

URLs must be reachable **by the peers** — the TURN server's public hostname, never a Docker service
name. Setting URLs without a secret (or the reverse) logs a loud warning and leaves TURN **disabled**
rather than handing clients an ICE server they cannot authenticate against.

### Deploy coturn

Use `deploy/docker-compose.turn.yml` with the production stack (or run coturn standalone). It needs a
public IP, its configured UDP/TCP/TLS listeners, and the actual relay-allocation range open. The
production overlay uses UDP 49160–49200; match firewall rules to its min-port/max-port settings.
See the [production TURN bring-up](guides/server-deployment.md#3-first-start).
The compose entry already carries
the `--denied-peer-ip` ranges that stop it becoming an open proxy into private address space —
**keep them**; a TURN server reachable from the internet without them will relay traffic into your
LAN for anyone who asks.

### Verify it, rather than assuming

Nothing about TURN is visible when it is working and unnecessary, so check the two places that
distinguish "not needed" from "misconfigured":

- **Agent/probe log:** `signaling: brokered … ice_total=2 ice_relay=1`. `ice_relay=0` means no TURN
  server was issued for the session — a configuration answer, not a connectivity mystery.
- **Browser:** `transport.gatheredCandidateKinds()` includes `"relayed"` once a relay candidate is
  gathered. Candidates are classified by their `typ` token.

---

## 7. What a real deployment still needs (checklist)

- **Secrets:** `GRANT_ISSUER_SEED` (stable), Postgres password, TURN shared secret. Store them in a
  secret manager, not in files/compose defaults.
- **TLS everywhere:** reverse proxy for `wss://` signaling, `https://` control-plane + viewer; set
  `CP_SECURE_COOKIE=1`.
- **Postgres:** connect `DATABASE_URL` as the dedicated non-superuser `rmt_app` role from
  `0005_app_role.sql` (RLS enforcement — a superuser/owner DSN silently bypasses tenant isolation);
  backups, `sslmode=require`.
- **coturn** for WAN symmetric-NAT clients (§6).
- **Agent provisioning at scale:** template `config.json` with your `signaling_url`,
  `control_plane_url` + `grant_issuer_pubkey`, leave `device_id` blank, and inject a per-machine
  `enrollment_token`; distribute `dist/agent` + `install-agent.ps1` via your RMM/GPO. Never bake
  `identity.key` or a `device_id` into an image (§4a).
- **Agent packaging:** `dist/agent/config.template.json` and `dist/agent/install-agent.ps1`
  are generated inline by `scripts/build-release.ps1`, and **that script's here-strings are the
  source of truth**. The generated installer takes
  `-ControlPlaneUrl` + `-EnrollmentToken`, runs `agent_host enroll`, aborts if enrollment fails or
  produces no `device_id`, and has **no `-DeviceId` parameter at all**; `-Unmanaged` is the explicit
  opt-out for a dev/LAN install. `build-release.ps1` fails the build if the template's key set
  drifts from `HelperConfig` in `crates/agent-windows/src/config.rs`, if the installer does not
  parse, if it gains a `DeviceId` parameter, if a staged binary imports a CRT DLL, or if the staged
  migrations are not contiguous `0001..NNNN`.
- **Enrollment tokens:** implemented (M1, migration `0007_enrollment.sql`). Mint/list/revoke via
  `POST|GET /enrollment-tokens` + `POST /enrollment-tokens/{id}/revoke` (`manage_enrollment`;
  plaintext shown once at mint, only the SHA-256 stored). Mint parameters are **bounded in both
  dimensions**, because a token is a distribution credential and bounding only one of them leaves
  the other open: `ttl_seconds` at `MaxEnrollmentTokenTTL` (30 days — compared in SECONDS before the
  conversion, so a value that would overflow `time.Duration` is refused instead of wrapping to a
  past expiry behind a 201) and `max_uses` at `MaxEnrollmentTokenUses` (500 — beyond the largest
  single-site rollout; past that, mint again and leave a fresh audit event). Defaults stay
  conservative (24 h, single-use), and both ceilings answer **400 rather than clamping**, so an
  operator is never handed a narrower token than the one they were told they minted. The use
  ceiling also keeps the value inside the 32-bit `enrollment_token.max_uses` column — uncapped, a
  request for 2^31 reached the INSERT and came back a 500. Installers redeem via the public
  `POST /enroll/redeem` `{token, pubkey, name?}` — atomic expiry/max-uses/revocation enforcement
  via `cp_enrollment_token_redeem`, agent Ed25519 pubkey pinned into `machine.pubkey`. The
  machine's `device_id` is **minted server-side and returned in the response**; a `device_id` in
  the request body is ignored (an unauthenticated caller choosing it would be choosing which agent
  that tenant's session tickets authorize). Redemption is rate-limited per source IP, its body is
  capped at 64 KiB and the `name` field at 255 characters (it is unauthenticated — nothing may be
  unbounded before a credential is checked), and it is refused outright once the token's tenant is
  suspended (migration `0011`). Token mint/list/revoke are scoped to the caller's **group**, not
  just their tenant: a token plants a machine into the group it names, so a group-scoped admin can
  neither mint into, nor see, nor revoke a token for a group they hold no rights over.
- **Credential provisioning / reset:** implemented (migration `0020`). `POST /me/password` refuses
  an account with no credential (a session alone must not mint a first password), so a first
  password — and a forgotten one — comes from a single-use, expiring, hash-at-rest setup token:
  `POST /users/{id}/password-reset` mints one (plaintext shown once; the caller re-proves their OWN
  password, may not target themselves, and may only target an account whose (capability, group)
  authority is a subset of their own), `DELETE` on the same route cancels outstanding links, and
  the PUBLIC `POST /auth/password/redeem` spends it. Redeeming **never touches `user_totp`** and
  **never issues a session**, so it re-provisions the first factor only. Minting supersedes the
  user's outstanding links under a per-user advisory lock, with a partial unique index
  (`uq_user_credential_token_one_live`) as the database-level backstop, so a double-click cannot
  leave two live takeover links behind. The public redeem meters INVALID tokens per source only —
  a lockout never refuses a genuine link, because behind a reverse proxy `clientIP` is the proxy
  for every caller and this endpoint IS the account-recovery path.
- **TOTP + CSRF:** implemented (M4). TOTP 2FA is enforced at `POST /auth/login` once an
  enrollment is confirmed (`/auth/totp/enroll` → `/auth/totp/confirm`); accounts without TOTP log
  in with password only. **Enrolling requires a step-up in both directions:** a FIRST enrollment
  requires the account's current **password** (otherwise a stolen session could arm the attacker's
  own authenticator on an account that had none, and the victim's later password change would no
  longer evict them — the second factor would be the attacker's), and an account with no local
  credential is answered 409 rather than allowed to arm a factor on a session alone. Re-enrolling
  on an account that already has confirmed TOTP requires a valid **current** code — the password is
  NOT accepted in its place — and only arms a *pending* secret (migration `0009`), so an abandoned
  or attacker-initiated re-enroll cannot silently downgrade the account to password-only;
  `totp.enroll`/`totp.confirm` and failed logins are recorded in `GET /audit`. `/auth/login`,
  `/auth/totp/*` and `/enroll/redeem` back off exponentially per account and per source IP after
  repeated failures (in-process counters — a multi-replica deployment should front them with a
  shared limiter). A TOTP code authenticates **once** (RFC 6238 §5.2, migration `0012`): the time
  step it matched is recorded and any code at or before that step is refused, so an observed code
  cannot be replayed for the rest of its ~90-second skew window. Cookie-authenticated mutating
  requests need the double-submit CSRF pair: login sets the non-HttpOnly `rmt_csrf` cookie and
  returns the same value as `csrf_token`, which the client echoes in `X-CSRF-Token` (Bearer-token
  requests are exempt; `/auth/login` and `/enroll/redeem` are public and exempt). That CSRF value is
  **derived from the session token**, so a cookie pair transplanted from another session is rejected
  even though its halves agree. `POST /auth/login` cannot double-submit (no session exists yet), so
  it is guarded instead by a browser-origin check — `Sec-Fetch-Site: cross-site`, or an `Origin`
  whose host is not the request's `Host`, is refused. This is what stops a cross-site
  auto-submitting form from logging a victim's browser into an ATTACKER-controlled account (the
  session cookie is `SameSite=Lax`, which permits exactly that navigation). Requests with neither
  header — non-browser clients — are unaffected. **A reverse proxy in front of the control plane
  must preserve the client's `Host` header** or the `Origin` fallback will see a mismatch.
- **Docker images:** build + smoke-test the authored Dockerfiles/compose in CI (unverified here).
