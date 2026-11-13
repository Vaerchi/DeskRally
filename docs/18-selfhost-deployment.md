# Self-hosting on one Linux box, exposed to the internet

This topology uses one Ubuntu host running Docker, with Windows agents dialing signaling
outbound. Agents can be on the server LAN or another network with appropriate connectivity.

The images and compose configuration were validated in CI. The gateway and TLS notes below
include deployment validation; follow the staged checks in §7 for each new deployment.

## The topology, and why the attack surface is smaller than it looks

```
   CLIENT                          INTERNET                    SERVER
  ┌────────┐                                          ┌──────────────────────────┐
  │browser │──── https://console.example.com ─────────────▶│ Caddy  (TLS, one origin) │
  │console │──── wss://console.example.com/ws ────────────▶│  ├─ /        viewer       │
  └────────┘                                          │  ├─ /cp/*    controlplane │
       ▲                                              │  └─ /ws      signaling    │
       │                                              │                          │
       │        WebRTC media (P2P, or via TURN)       │ postgres  (LAN only)     │
       └──────────────────────────────────────────────│ coturn    (own IP)       │
                                                      └──────────────────────────┘
                                                          │ LAN
                                                    ┌─────┴──────┐
                                                    │ Windows    │  agents reach
                                                    │ agents     │  signaling over
                                                    └────────────┘  the LAN — no
                                                                    exposure needed
```

**The agents need no inbound exposure at all.** They are on the same LAN as the server and dial
signaling internally. Only the console-facing surface has to face the internet, which is a much
smaller thing than "expose the remote-control server".

| Service | Port | Expose? | Why |
|---|---|---|---|
| Caddy (viewer + `/cp` + `/ws`) | 80/443 | **yes** | the only public listener |
| control-plane | 8081 | no — internal | reached via Caddy `/cp` |
| signaling | 8080 | no — internal | reached via Caddy `/ws` |
| relay | 9000 (TCP) | **no** | see below |
| coturn | 3478 + a relay range | **when needed** | see §4 |
| postgres | 5432 | **never** | LAN only |

**The relay does not need exposing.** The browser console does not implement the relay fallback at
all — `web/viewer/src/lib/transport.ts` says so in as many words ("the non-ICE fallback transport
… which this browser client does not implement"). It is the Rust agent's raw-TCP fallback
(`agent-core/src/relay_transport.rs`). For a browser→agent session the NAT fallback is **TURN**, not
the relay.

## 1. Why one origin, and why no viewer rebuild is needed

The console defaults its control-plane base URL to the path prefix **`/cp`**
(`web/viewer/src/lib/controlplane.ts`), and the dev proxy strips that prefix before forwarding
(`vite.config.ts`: `rewrite: path.replace(/^\/cp/, "")`). Reproduce exactly that in production and
the shipped bundle works **unmodified** — no `VITE_CONTROL_PLANE_URL`, no rebuild per deployment.

Caddy's `handle_path` strips the matched prefix, which is precisely the dev proxy's behaviour:

```caddyfile
console.example.com.com {
	encode zstd gzip

	# Control-plane API. handle_path STRIPS /cp, matching vite.config.ts's rewrite exactly, so the
	# shipped bundle's default base URL works with no rebuild.
	handle_path /cp/* {
		reverse_proxy controlplane:8081
	}

	# Signaling WebSocket. Caddy upgrades transparently; no extra directives needed.
	reverse_proxy /ws signaling:8080

	# The viewer bundle. `join.html` is a byte-identical copy of index.html (build-release.ps1
	# ships it that way), so the attended-guest /join entry point works with no rewriting.
	root * /srv/viewer
	file_server
}
```

The **signaling URL is not baked into the bundle** either: the control plane hands it to the console
alongside the session ticket, from `CP_SIGNALING_URL`. One server-side variable.

## 2. The compose overlay

`deploy/docker-compose.yml` stays as-is — it is the documented LAN/dev bring-up and publishes
8080/8081/9000/9001 on `0.0.0.0`, which is right for a laptop and wrong for an internet-facing host.
`deploy/docker-compose.prod.yml` is an **overlay** that adds Caddy and withdraws those publications:

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.prod.yml up -d --build
```

Two things it does, both deliberate:

* **`ports: !reset []` on signaling, relay and controlplane.** They keep talking to each other over
  the compose network by service name; they simply stop listening on the host. On an internet-facing
  box those four published listeners are surface nobody needs.
* **Caddy publishes on ONE host IP**, not `0.0.0.0` — see §3.

### `!reset`, and why a bare `[]` is a trap

The overlay first used `ports: []`, on the reasonable assumption that a later file replaces an
earlier one's sequence. **It does not.** Compose **CONCATENATES** `ports` — it is one of the
documented multi-value options (with `expose`, `external_links`, `dns`, `dns_search`, `tmpfs`) that
merge rather than replace — so the empty list was appended to the base's and every publication
survived untouched.

That is a silent failure of exactly the kind this deployment cannot afford: the stack would have come
up looking correct, with four extra listeners on a public host, and nothing would have said so. CI
caught it on the very first run — `FAIL: signaling still publishes 1 host port(s) under the prod
overlay` — because the assertion checks the MERGED config rather than trusting the merge semantics.
It carries two negative controls (Caddy must still publish; the base file must publish something to
withdraw) so it cannot pass vacuously on a config that exposes nothing at all.

`!reset` is the documented way to remove an attribute during a merge and **requires Docker Compose
v2.24.4 or newer**. On an older Compose the tag is a parse error — which is the correct failure
direction: loud at bring-up, rather than silently publishing what you meant to withdraw. **Check
`docker compose version` on the target host before the first bring-up.**

## 3. A second IP, and what it does and does not buy

When a host runs other services, giving this stack its own address (and its own public IP)
can avoid port conflicts:

* **80/443 are free** independently of other services.
* **Its own hostname and ACME certificate**, independent of anything else on the box.
* **Per-IP firewall rules** on the gateway; the two services' rules never interact.
* **The coturn port-range collision disappears.** Sockets bind to `(address, port)`, not to a port
  alone, so coturn holding a relay range on IP-B does not conflict with another service's outbound
  ephemeral sockets on IP-A. **Only if coturn binds explicitly** — `--listening-ip` / `--relay-ip`.
  Bound to `0.0.0.0` it takes those ports on every address and the conflict returns.

Publish Caddy to that address only:

```yaml
caddy:
  ports:
    - "${PUBLIC_IP}:80:80"
    - "${PUBLIC_IP}:443:443"
```

**What it does NOT buy: isolation.** Both services still share a kernel, a Docker daemon and a
filesystem. If the other service is compromised, this stack is on the same host — and this stack can
drive managed endpoints. A second IP solves ports, DNS and certificates; it is not a security
boundary. Real separation is a second VM or a second box. Partial mitigation already in place: all
three images run **non-root** (`adduser -D -u 10001 app` + `USER app` in every Dockerfile).

## 4. coturn — the one awkward service

The Go relay is **not** a TURN server. For a browser→agent session across two NATs,
TURN is the fallback, and coturn needs a public IP, UDP+TCP 3478, and a relayed UDP port range.

**Start without it.** STUN alone handles many NAT configurations; TURN is for symmetric
NAT and networks that block UDP between the peers. Skipping it initially removes the widest firewall
rule from the picture, and its absence fails visibly (sessions don't connect) rather than silently.

When you do enable it, three things matter:

1. **Narrow the relay range.** The commented service in `docker-compose.yml` uses coturn's default
   `49152–65535`, which overlaps Linux's ephemeral range (`net.ipv4.ip_local_port_range`, default
   32768–60999). A handful of concurrent sessions needs a handful of ports: `--min-port=49160
   --max-port=49300` is ample and turns a 16,000-port firewall rule into ~140.
2. **Bind explicitly** to the stack's own IP, per §3.
3. **`--external-ip=<PUBLIC>/<PRIVATE>` if it is behind 1:1 NAT.** Without it coturn advertises relay
   candidates carrying its *private* address, every client tries to reach an RFC1918 address, and
   TURN fails **silently** — no error anywhere, sessions simply never establish. This is the single
   most common coturn misconfiguration and it is invisible in logs.
4. **Keep the `--denied-peer-ip` ranges.** A TURN server on the internet without them is an open
   proxy into whatever it can reach — including the LAN full of machines this product manages.

## 4b. The control plane must NOT connect as the superuser

**A defect in the shipped compose file, found 2026-08-26 while writing the bring-up steps.**

`deploy/docker-compose.yml` builds `DATABASE_URL` from `${POSTGRES_USER}` — which is the postgres
image's **bootstrap superuser**. The DSN "MUST connect as the
least-privilege `rmt_app` role (RLS-subject), NOT postgres/owner", and `migrations/0005`'s own header
says the same. The containerised control plane was violating both.

The severity needed checking rather than assuming, and the check cuts one way and not the other:

* **All 13 RLS-protected tables carry `FORCE ROW LEVEL SECURITY`**, not merely `ENABLE`. `FORCE` makes
  the policies apply to the table **OWNER** too, which is the usual way this goes wrong — so that
  half is genuinely defended.
* **But a SUPERUSER bypasses row-level security unconditionally**, and `FORCE` does not touch that.
  `POSTGRES_USER` is the bootstrap superuser. So RLS was off for the control plane.

For a single-tenant self-host the practical impact today is nil — there is nothing to isolate from.
It matters because it is a documented hard rule violated by the artifact, and because it disarms the
multi-tenant guarantee **silently**: nothing logs it, no test covers the compose DSN, and the day a
second tenant exists the isolation everyone assumes is simply absent.

**Fixed in the prod overlay, in two halves that only work together:**

1. **The migration runner provisions the password** (`ProvisionAppRolePassword`, §4c), immediately
   after applying migrations. 0005 deliberately ships no password — *"production provisions the
   password/DSN out-of-band so no throwaway secret is committed to a migration"* — and `rmt_app` does
   not exist until 0005 has run, so the provisioning has to come after it.
2. The overlay points `DATABASE_URL` at `rmt_app`. That role is `NOSUPERUSER NOBYPASSRLS`, so RLS
   applies to it.

`APP_DB_PASSWORD` is `:?`-required, so a bring-up that forgot it fails loudly instead of falling back
to the superuser DSN.

**This deliberately does NOT live in `/docker-entrypoint-initdb.d`.** A first draft did, as
`deploy/initdb-prod/zz-rmt-app-password.sh`. Init scripts run on the **first init of an empty volume
only**, so every subsequent deploy — the entire point of §4c — would have skipped it, and rotating
the password would have meant destroying the volume. Folding it into the runner makes it idempotent
and re-run on every deploy, which is also what makes rotation a matter of changing `.env` and
redeploying.

The statement is built by **Postgres** (`format('… %L', $1)` in a plain `SELECT`, then Exec the
result), never quoted in Go: the value lands in privileged DDL run as the owner, so hand-rolled
escaping there would be an injection.

## 4c. Schema migrations, and why automated deploy needed a runner first

**Built 2026-08-26.** Before it, migrations were applied two ways and neither survives an *update*:
Postgres's `/docker-entrypoint-initdb.d` (first init of an empty volume only) and a hand-run
`for f in migrations/*.sql; do psql -f "$f"; done`. Nothing recorded what had run, and
nothing could — there was no ledger. Re-running the set blindly is not an option either: **24 of the
`CREATE TABLE` statements carry no `IF NOT EXISTS`**, so a second pass dies on the first file.

That is survivable for a machine set up once by hand. It is the blocker for automated deploy: this
project added 38 migrations in ~91 loops, so a pipeline without a runner works right up until the
first schema change and then takes the control plane down.

`controlplane migrate` — a subcommand of the same binary, so the deployed image needs no second
artifact to keep in step with the schema it applies.

| Behaviour | Why |
|---|---|
| Ledger in `schema_migration` | a second run is a **no-op**; the property redeploy rests on |
| One transaction per file | no migration uses `CREATE INDEX CONCURRENTLY` (checked), so a failure leaves the file wholly unapplied — and the ledger row commits *with* it, so the two can never disagree |
| SHA-256 recorded and re-checked | an **edited** already-applied migration is a hard failure. Silent schema drift between a dev box and production is invisible without a digest |
| Numeric version ordering | every file today is 4-digit padded so lexical agrees *by accident*; note that `0100` sorts before `0009` under a plain sort |
| Duplicate versions refused | two files claiming `0039` would apply in filesystem order — works on one machine, not another |
| Baselining is **explicit** | a pre-runner database has the schema but no ledger. Auto-adopting assumes every on-disk migration ran, which is right on a full database and destructive on a half-migrated one. It refuses and asks for `--baseline` |

**It runs as the OWNER, via `MIGRATE_DATABASE_URL` — not `DATABASE_URL`.** `rmt_app` is
`NOSUPERUSER` with DML grants only and has no DDL rights at all, deliberately. Two DSNs is the point,
not duplication: one role that can change the schema, another that the application uses and that RLS
applies to.

**A third role owns the definer functions (migration 0076).** Every application
`SECURITY DEFINER` routine runs as its owner, which used to be this migration role (a superuser in
production). They are now owned by `rmt_definer`: `NOLOGIN`, no superuser/createdb/createrole/replication,
`BYPASSRLS` (the pre-tenant lookups exist to bypass RLS), owner of no table, with table privileges
granted one by one in 0076. The migration role must still be a superuser (only one can grant
`BYPASSRLS`); 0076 refuses to run otherwise. A definer function added by a later migration must end with
`ALTER ROUTINE ... OWNER TO rmt_definer`, and a full-migrate test fails if one does not.

**It also provisions `rmt_app`'s password**, after the migrations, because 0005 is what creates the
role. That folds in §4b's fix and removes an ordering trap: an init script would have run *before*
0005. The `ALTER ROLE` statement is built by **Postgres** (`format(…%L…)` in a plain `SELECT`), not
escaped in Go — the value lands in privileged DDL run as the owner, so hand-rolled quoting there
would be an injection. A first attempt used `DO $$ … format(…, $1) … $$`, which cannot work: inside
a dollar-quoted block `$1` is quoting syntax, not a placeholder. The test caught it.

**Compose wiring:** a one-shot `migrate` service that `controlplane` waits on with
`condition: service_completed_successfully` — with a plain `depends_on` the server would start
alongside a *failed* migration and 500 on every route touching a column that does not exist yet. The
prod overlay also **drops the base file's initdb mount** (`volumes: !reset`), so the runner is the
sole applier; leaving both would make the first bring-up find a fully-migrated database with no
ledger, which the runner correctly refuses.

**Verification:** 6 unit tests (ordering, duplicates, stray files, hashing, empty dir, and the real
repository's own migrations), 7 live-Postgres tests (idempotence, drift, atomicity, baseline, fresh
database, provisioning, metacharacter passwords), and **7 mutations of the new guards, all lethal**.

## 5. The settings that matter once it is public

| Variable | Value | Why |
|---|---|---|
| `CP_SECURE_COOKIE` | `1` | mandatory over HTTPS; the session cookie is the console's auth |
| `CP_TRUST_PROXY_IP` | `1` | **only** behind exactly one reverse proxy — Caddy here. Without it the allow-list below sees Caddy's IP, not the client's, and so does the audit trail's **Source IP** column (trust only the configured proxy) |
| `CP_ADMIN_IP_ALLOWLIST` | office CIDR | the highest-value single control; see the limit below |
| `GRANT_ISSUER_SEED` | `openssl rand -hex 32` | must be **stable and secret**. Unset ⇒ a fresh key each boot ⇒ every enrolled agent rejects new grants |
| `SIGNALING_TICKET_PUBKEY` | the CP's `grant_issuer_pubkey` | signaling **refuses to start** without it. Never pass `-insecure-no-ticket-verification` on a public box |
| `CP_DEVICE_IDENTITY_TOKEN` | 32+ random chars | lets signaling verify an agent's proof of possession |
| `CP_SIGNALING_URL` | `wss://console.example.com/ws` | what the console is told to dial |
| `PRESENCE_TOKEN` | random | must match on both services, or the access panel reports presence unknown. Fails soft |

Already true without configuration, and worth knowing:

* **Login throttling is ON by default** (`control-plane/auth.go`; `DisableThrottle` exists only for
  tests that deliberately hammer an endpoint).
* **A malformed `CP_ADMIN_IP_ALLOWLIST` is a hard startup failure**, never a silent widening.
* **The allow-list runs at the edge**, before auth and CSRF.

**Two honest limits.** The allow-list covers the **authenticated console API only** — agent-enroll
and guest-attend routes stay open by design (they carry their own bearer authorization), and
signaling must be reachable. It narrows the blast radius; it does not eliminate exposure. And
**TOTP has no deployment-wide enforcement flag**: the mechanism is real and pg-tested (single-use
step consumption, replay-protected), but deployment-wide mandatory 2FA is not provided here. Enroll it per-account and do not assume org-wide
enforcement exists.

## 6. TLS is not optional — and not for the reason you would guess

**Use TLS from the start.** The console requires a secure browser context as well as encrypted login traffic.

**The console calls `crypto.randomUUID()` in its CONNECT path** — `web/viewer/src/App.tsx`,
registering the controller identity before `connect_request` — and **there is no fallback anywhere**
(three call sites, none guarded). That API is **secure-context only**. Served over plain `http://` to
anything other than `localhost` it is `undefined`, so the console **throws on connect** instead of
degrading. The symptom looks nothing like a missing certificate, and a "let's just try it on the LAN
first over HTTP" step would have burned an evening on it.

The clipboard path, by contrast, IS guarded (`App.tsx` substitutes a shim when
`navigator.clipboard` is absent, and `ClipboardControl.tsx` documents the requirement) — so
clipboard degrades politely while connect does not. Do not generalise from one to the other.

The only two safe non-public options: **`localhost`**, browsed on the server box itself (a secure
context by definition), or a real hostname with Caddy's **`tls internal`** whose local CA you trust
on the client. A bare IP over HTTP is not one of them.

## 7. Order of operations

Staged so each step fails in isolation — the staging is about **blast radius**, not about TLS:

1. **`docker compose build`.** Verified in CI as of 2026-08-26, so this should be uneventful; it is
   still the step everything downstream assumes worked.
2. **Bring the stack up behind Caddy with a real certificate**, on the real hostname, exposed. Apply
   the migrations, provision an owner and log in — `DATABASE_URL` set means the **real**
   authenticator, not `StubAuthenticator`. Verify this path independently before enrolling agents.
3. **Enroll exactly ONE Windows machine** and prove a session end to end. Not the fleet — see below.
4. **Then enroll the rest**, and only then worry about coturn: add it when a network actually needs
   it, not pre-emptively. Its absence fails visibly (sessions do not connect); its misconfiguration
   fails silently (§4).

**Why one machine first.** Validate enrollment and session behavior before scaling the fleet.
MSI-installed agents support [automatic updates](33-agent-auto-update.md), including an idle
barrier and health-gated rollback; bootstrap and recovery still require installation planning.

## 8. Gateway notes (static IP)

* Forward **443**. Certificate issuance was validated with **tls-alpn-01** when port 80
  was unavailable; an initial http-01 timeout can be followed by successful tls-alpn-01.
  Forward 80 for HTTP-to-HTTPS redirects and an ACME fallback if desired.
  Scope gateway forwarding by destination IP, for example
  `198.51.100.58:443 → 192.0.2.6:443`; hostname changes do not change this mapping.

* **A real DNS name must resolve to that IP before first bring-up.** Caddy requests the certificate
  on startup; without working DNS it retries and serves nothing, and Let's Encrypt rate-limits
  repeated failures.
* Do **not** forward the NAS/DSM management interface, Postgres, or the relay.
* Confirm how the gateway presents the second public IP — a **routed** block needs no `--external-ip`
  on coturn; **1:1 NAT** does. Getting this wrong is the silent-TURN-failure above.
* **Watch IDS/IPS.** Aggressive Threat Management has a habit of interfering with long-lived
  WebSockets and high-rate UDP. If sessions drop oddly, test that by exception early — it is a
  cheap thing to rule out and an expensive thing to chase.
* Consider putting the host on its own VLAN with only the forwarded ports allowed inbound.

## 9. What this document does not cover

* **HA or horizontal scale.** `Registry` is a `map[string]*Peer` behind a mutex and the broker's
  sessions are in-memory; there is no Redis/etcd/NATS anywhere in the servers. **Both peers of a
  session must reach the same signaling process**, so this is a single-instance design today. That
  is exactly the open P1 work (`HA and horizontal relay scale`, `Regional relay pools`).
* **Backups.** Postgres holds every tenant, machine, user and audit chain. Nothing here backs it up.
* **Agent auto-update details.** See [agent auto-update](33-agent-auto-update.md) for the MSI updater,
  bootstrap requirements and recovery limits.
