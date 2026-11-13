# Deploying the DeskRally server

For native Windows or Linux deployment without Docker, see [the native server guide](/docs/native).
This guide covers the established Docker installation path. Native deployment is in preview.

For the detailed material, use the [full build and deployment reference](../10-deployment.md),
[server configuration and complete environment template](server-configuration.md),
[encrypted backup and restore runbook](../22-backup-and-restore.md), and
[connection troubleshooting](../connection-troubleshooting.md).

This guide is for an operator self-hosting DeskRally on one Linux host. It covers:
- the control plane, with Postgres and row-level security;
- the signaling server and the relay;
- coturn (TURN);
- Caddy, which serves the web console and `/download`.

All of it runs under Docker Compose. Commands run from the repository root unless noted.

There are two ways to install:

- **Release package (recommended).** Download one file and run `install.sh`. It needs only Docker:
  no source code, Go, Node or build machine. See [Quick install](#quick-install-from-the-release-package).
- **From source.** Build the images and the console yourself. Sections 2–3 describe this; they are
  also the reference for every setting `install.sh` writes.

> **Validation scope.** Some source-install steps have not been exercised end to end on a fresh
> host and are marked *(not yet exercised)*. Validate your deployment, including TURN, before rollout.

## 1. What you need

**Host.**
- One Linux server (Ubuntu is the tested target).
- The design is single-instance: signaling keeps its peer registry in memory, so there is no
  high availability.

**Docker.**
- Docker Engine with **Compose v2.24.4 or newer**. The production overlay relies on the `!reset`
  and `!override` tags; older Compose silently keeps ports published.
- Install it with:
  ```bash
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER"   # log out and back in
  ```

**Node 20 or newer**, to build the web console. Check `node --version`: a failed
`apt-get update` can leave you on Node 12.

**Two public IPv4 addresses.**

| Address | DNS name | Used by |
|---|---|---|
| IP-A | `remote.example.com` (your `SITE_ADDRESS`) | Caddy: the console, the API under `/cp`, signaling under `/ws`, `/download` |
| IP-B | `turn.example.com` | coturn: STUN/TURN on 3478, and TURN-over-TLS on **443** |

TURN gets its own address so that TURNS can listen on 443, the one port almost every network
allows, without clashing with the website. **TURN is required.** Without it, sessions between
machines on different networks fail to connect.

**DNS must resolve before the first start.** Caddy requests its certificates at startup, and
Let's Encrypt rate-limits repeated failures.

**Firewall and port forwards.**

| Public | Port(s) | Forward to the host |
|---|---|---|
| IP-A | TCP 443 | 443 (Caddy) |
| IP-A | TCP 80 | 80 (optional; certificates issue over 443 alone) |
| IP-B | UDP + TCP 3478 | 3478 |
| IP-B | TCP 443 | 5349 (coturn TLS) |
| IP-B | TCP 80 | 80 (lets Caddy obtain the TURN hostname's certificate) |
| IP-B | UDP 49160–49200 | the same range (relay ports) |

Never expose 5432, 8080, 8081, 9000 or 9001.

**HTTPS is mandatory.** The console uses browser APIs that only exist on secure pages, so plain
HTTP or a bare IP address will not work.

**Copying the tree from a Windows checkout?** Keep LF line endings:
```bash
git -c core.autocrlf=false archive HEAD | tar -x -C ~/deskrally
```
CRLF breaks the Docker builds with a `bad interpreter` error.

## Quick install from the release package

Validate installation, health checks, owner creation, idempotent re-runs, reboot recovery and a
complete browser session to an enrolled computer. Same-subnet testing does not exercise TURN;
test connectivity across networks separately.

**Trying it on a private network.** Without public DNS, Let's Encrypt cannot issue a certificate.
Instead, give the site a name under `.internal` (for example
`./install.sh --site console.example.internal ...`). Caddy then issues the certificate from its own
local authority automatically, with no configuration change. Every client must trust that authority
and resolve the name:
- Copy the root certificate off the server (with the `dc` alias defined below):
  `dc exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > deskrally-root.crt`.
- On each Windows computer, import it into **Local Machine → Trusted Root Certification
  Authorities**. The agent uses the Windows trust store, so a per-user import is not enough. Do the
  same in the browser used for the console.
- Make the name resolve to the server, through local DNS or a hosts-file entry.

Use this for evaluation only. A private CA and hosts entries are not a production setup.

1. Complete section 1 first: DNS, ports, Docker.
2. Download and check the official package from the hosted DeskRally service:
   ```bash
   curl -fsSLO https://main.deskrally.com/download/server/latest.json && cat latest.json
   V=0.1.6   # the "version" from latest.json
   curl -fsSLO https://main.deskrally.com/download/server/deskrally-server-$V.tar.gz
   curl -fsSL  https://main.deskrally.com/download/server/deskrally-server-$V.tar.gz.sha256.txt | sha256sum -c -
   ```
3. Extract it and run the installer:
   ```bash
   sudo mkdir -p /opt/deskrally && sudo chown "$USER" /opt/deskrally
   tar -xzf deskrally-server-$V.tar.gz -C /opt/deskrally && cd /opt/deskrally/deskrally-server-$V
   ./install.sh --site remote.example.com --public-ip <IP-A>                 --owner-email you@example.com --tenant main --org-name "Example Co"
   ```

`install.sh` then does all of the following:
- loads the prebuilt images;
- creates `deploy/.env` with freshly generated secrets;
- starts the database and runs the migrations;
- records the grant issuer key;
- starts every service and waits until it is healthy;
- creates the first owner account.

The owner's one-time password is saved in `owner-credentials.txt`. Sign in at
`https://remote.example.com/console`, change the password, set up two-factor sign-in, then delete
that file.

Running `install.sh` again is safe: it never replaces an existing secret.

**After the quick install,** do these separately:
- TURN (section 2, "TURN", then the TURN start command in section 3);
- backups (section 6);
- optionally the managed installer (section 5).

Always add `-f deploy/docker-compose.release.yml` to the compose command:
```bash
alias dc='docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.prod.yml -f deploy/docker-compose.release.yml'
```

**Upgrading a package install.**
1. Extract the new package next to the old one.
2. Run `./install.sh --upgrade-from /opt/deskrally/deskrally-server-<old>` from the **new**
   directory. It copies `deploy/.env` and the published downloads, then starts the new version
   (migrations run automatically).
3. Keep the old directory until you are satisfied. To roll back, run `dc up -d` from the old
   directory. Schema changes are not rolled back.

**What the package does not include.** The prebuilt Windows support tool (`DeskRallySupport.exe`)
and the installer bundle's `DeskRallySetup.exe` have the hosted service's address built in, and
official agents trust the hosted service's update identity when built with
`DESKRALLY_UPDATE_OFFICIAL=1`. A server on your own domain needs its
own Windows builds of those (section 5). Agents installed with the MSI and a provisioning file work
with any server.

## 2. Configure `deploy/.env`

```bash
cp deploy/.env.example deploy/.env      # deploy/.env is git-ignored; never commit it
```

Generate the secrets:
```bash
for k in POSTGRES_PASSWORD APP_DB_PASSWORD; do echo "$k=$(openssl rand -hex 24)"; done
for k in GRANT_ISSUER_SEED CP_DEVICE_IDENTITY_TOKEN PRESENCE_TOKEN TOTP_ENCRYPTION_KEY TURN_SHARED_SECRET; do echo "$k=$(openssl rand -hex 32)"; done
```

### Required

Compose refuses to start without these.

| Variable | Value |
|---|---|
| `POSTGRES_PASSWORD` | Random. The database owner; used only by migrations, admin commands and backups. |
| `APP_DB_PASSWORD` | Random. The least-privilege `rmt_app` role the control plane connects as. Row-level security applies to it. |
| `GRANT_ISSUER_SEED` | Random, 64 hex characters. **Never change it after agents enroll:** every agent pins the public key derived from it, and a new seed makes them all reject sessions. Back it up. |
| `SIGNALING_TICKET_PUBKEY` | The public half of the seed. Leave the 64-zero placeholder for the first start, then fill it in (step 3). |
| `CP_DEVICE_IDENTITY_TOKEN` | Random, at least 32 characters. Shared secret between signaling and the control plane. |
| `CP_SIGNALING_URL` | `wss://remote.example.com/ws` |
| `SITE_ADDRESS` | `remote.example.com` |

### Strongly recommended

| Variable | Value |
|---|---|
| `TOTP_ENCRYPTION_KEY` | Random, 64 hex characters. Without it, two-factor enrollment is refused **and Microsoft sign-in (SSO) cannot be configured**: it also encrypts the SSO client secret. |
| `PRESENCE_TOKEN` | Random, at least 32 characters. Without it, machines show presence as "unknown". |
| `PUBLIC_IP` | IP-A, so Caddy binds only the website address. |
| `SIGNALING_ALLOWED_ORIGINS` | Optional. Blank = derived from `SITE_ADDRESS` (a single host or a comma/space list such as `console.example.com, tenant.example.com`; each host becomes `https://host`; a scheme, port or wildcard there stops signaling at startup). Set it explicitly (e.g. `https://remote.example.com`) to override; an explicit value always wins. |
| `CP_TENANT_HOST_SUFFIX` | Needed only for Microsoft sign-in: the domain after the tenant slug, e.g. `.example.com`. **The example file ships `.deskrally.com`; change or blank it.** |
| `CP_TRUSTED_PROXIES`, `SIGNALING_TRUSTED_PROXIES` | Caddy's Docker network range, so rate limits see real client addresses. After the first start, run `docker network inspect deploy_default \| grep Subnet`. Neither variable is in the example file; add them. |
| `SIGNALING_MAX_CONNECTIONS_PER_IP` | e.g. `32`. Per-address connection cap. Pair it with `SIGNALING_TRUSTED_PROXIES`. |
| `CP_ADMIN_IP_ALLOWLIST` | Optional CIDR list allowed to use the console API. A malformed entry stops the control plane. |

Other notes:
- `SIGNALING_MAX_MESSAGES_PER_SECOND` defaults to 200 in production.
- `CP_SECURE_COOKIE=1` is already the production default.

### TURN

These are used together with `deploy/docker-compose.turn.yml`.

| Variable | Value |
|---|---|
| `TURN_SHARED_SECRET` | Random. coturn and signaling must share it. |
| `TURN_EXTERNAL_IP` | `<IP-B public>/<host private IP>` |
| `TURN_RELAY_IP` | The host's private IP. |
| `TURN_REALM` | e.g. `turn.example.com` |
| `STUN_URLS` | `stun:turn.example.com:3478` |
| `TURN_URLS` | `turn:turn.example.com:3478?transport=udp,turn:turn.example.com:3478?transport=tcp,turns:turn.example.com:443?transport=tcp` |

Set `TURN_SITE_ADDRESS` to your TURN hostname, e.g. `turn.example.com`. Caddy then obtains and
renews that name's certificate, which coturn reads. `install.sh` sets it to `turn.<SITE_ADDRESS>`.
If it is unset, it defaults to the hosted service's name, which is wrong for your install.

Setting the TURN URLs without the secret, or the reverse, leaves TURN disabled, and signaling
logs a warning.

Check the whole configuration before starting anything:
```bash
alias dc='docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.prod.yml'
dc config --quiet      # names any missing required variable
```
Always use both files. The base file alone is a development stack: it publishes the database and
service ports and relaxes database safety checks.

## 3. First start

**Build the console bundle:**
```bash
(cd web/viewer && npm ci && npm run build)
mkdir -p dist/viewer dist/artifacts
cp -r web/viewer/dist/* dist/viewer/ && cp dist/viewer/index.html dist/viewer/join.html
```

**Stage 1: database and control plane.** Read the grant issuer public key:
```bash
dc up -d postgres controlplane
for i in $(seq 1 30); do dc logs controlplane 2>/dev/null | grep -q grant_issuer_pubkey && break; sleep 2; done
dc logs controlplane | grep grant_issuer_pubkey     # control-plane: grant_issuer_pubkey=<64 hex>
```
Put that value in `SIGNALING_TICKET_PUBKEY` in `deploy/.env`. (Later you can read it with an API
token: `GET https://remote.example.com/cp/grant/pubkey`.)

**Check the migrations.** The `migrate` service applies `control-plane/migrations/*.sql` once,
records each file's SHA-256, and exits 0:
```bash
dc logs migrate
dc exec postgres psql -U rmt -d rmt -c 'SELECT count(*) FROM schema_migration;'
```
The count should equal the number of migration files. Never edit a migration that has already been
applied: the runner refuses a changed file.

**Stage 2: everything.**
```bash
dc up -d && dc ps                     # all services running; "migrate" exited (0)
curl -s https://remote.example.com/cp/healthz; echo   # prints: ok
```

**Start TURN:**
```bash
cd deploy
./turn-cert-sync.sh        # first: export the TURN certificate for non-root coturn
docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.turn.yml up -d --force-recreate signaling coturn
```
- `deploy/turn-cert-sync.sh` validates and copies ONLY the TURN name's certificate out of the `deploy_caddydata` volume into a dedicated `deploy_turncerts` volume (read-only for the non-root coturn), restarts coturn when it changes and verifies a real TLS handshake; run it daily from `deploy/turn-cert-sync.timer`. Non-root coturn cannot bind ports below 1024 unless the host sysctl permits it. See the [TURN transport and credential reference](../10-deployment.md#6-enabling-turn-for-wan). If your Compose
  project has a different name, set `CADDYDATA_VOLUME`.
- From then on, include `docker-compose.turn.yml` in every command that recreates signaling or
  coturn.

## 4. Create the first account

```bash
dc run --rm migrate bootstrap -tenant main -name "Example Co" -email you@example.com 2>&1 | tee ~/owner-credentials.txt
```
- It runs through the `migrate` service on purpose: only the database owner may create a tenant,
  and the control plane connects as the restricted `rmt_app` role.
- The **password is printed once**; only its hash is stored.
- Sign in at `https://remote.example.com/console` with that email and password, then:
  1. change the password (DeskRally menu → **My account**);
  2. set up two-factor sign-in.
- Make the tenant slug (`-tenant`) match the subdomain; the sign-in form fills it in from the
  address.
- Running `bootstrap` a second time is refused.
- Lost the owner password? Run
  `dc run --rm controlplane reset-password -tenant main -email you@example.com`.

## 5. Publish installers and updates under `/download`

Caddy serves only an allow-list from `dist/artifacts` (`ARTIFACT_DIR`); every other path is a 404.

| Path | Content |
|---|---|
| `/download/DeskRallySupport.exe` and `.sha256.txt` | The support tool guests run for attended sessions |
| `/download/client/manifest.json`, `/download/client/releases/X.Y.Z/DeskRallyClient.exe` | Desktop app updates |
| `/download/agent/v2/{canary,early,general}/manifest.json` | Signed agent update manifests (agent 1.3.0 and later) |
| `/download/agent/releases/X.Y.Z/DeskRallyAgent.msi` | Agent MSI payloads |

**Your Windows binaries: the build kit.** The guest support tool and the one-click installer have
the server address built in, so a server on your own domain needs its own build. This needs one
Windows machine, used once per release. The build signs everything with **your** code-signing
certificate. See the [source build and codec prerequisites](../10-deployment.md#1-prerequisites).

1. **On a Windows 10/11 machine with this repository checked out,** in an elevated PowerShell:
   ```powershell
   .\scripts\install-windows-build-prereqs.ps1
   ```
   This installs VS Build Tools, Rust, Git, vcpkg with libvpx/opus, and WiX. It skips anything
   already present. Then open a new terminal.
2. **Build:**
   ```powershell
   .\scripts\build-windows-kit.ps1 -ServerUrl https://remote.example.com `
       -GrantIssuerPubkey <from: dc logs controlplane | grep grant_issuer_pubkey> `
       -Sign Thumbprint -CertThumbprint <your code-signing certificate thumbprint> `
       -OutDir C:\deskrally-kit\<version>
   ```
   - `-Sign Unsigned` works for testing; Windows will then show "Unknown publisher".
   - `-Sign Script -SignScript <path>` calls your own signing script, such as a cloud signing
     service, once per file.
3. **What you get:**
   - `DeskRallyAgent.msi`, `DeskRallySetup.exe` and `DeskRallySupport.exe`, each signed before
     anything is hashed;
   - `installer-manifest.json`;
   - `SHA256SUMS`;
   - a README listing where each file goes.

   Copy `DeskRallySupport.exe` and its `.sha256.txt` to `dist/artifacts/` on the server, and the
   four installer files to `MANAGED_INSTALL_HOST_DIR` (below). Then run
   `dc up -d --force-recreate caddy controlplane`. Files must exist before the containers are
   created; a plain `restart` keeps stale mounts.

**Agent updates for kit-built agents.**
- **None (default):** source and kit builds have no update identity; auto-update is off.
- **Official (opt-in):** pass `-OfficialUpdates` to the kit, or set `DESKRALLY_UPDATE_OFFICIAL=1`
  for a direct source build. This trusts the checked-in official feed, update key and publisher.
  Official updates keep your server settings. The selector accepts only `1` (or empty/unset),
  and cannot be combined with own-feed inputs or the `update-test-feed` feature.
- **To run your own update feed**, add all three of:
  - `-UpdateFeed https://updates.example.com`
  - `-UpdatePubkeyFile <your update public key>`
  - `-UpdatePublisher "<your certificate subject>"`

  For direct source builds, set `DESKRALLY_UPDATE_FEED`, `DESKRALLY_UPDATE_PUBKEY_FILE`, and
  `DESKRALLY_UPDATE_PUBLISHER` together. Partial selections fail the build.
  Your agents then accept only your signed updates. Official DeskRally updates never reach them.

For the desktop client, `clients/windows/build-client.ps1 -OfficialUpdates` opts into the
official identity. Without update options, self-update is disabled; select your own identity
with `-UpdateHost` and `-UpdatePublisher`.

**Agent updates.**
1. Upload the MSI to `agent/releases/<version>/` **first**.
2. Then upload the signed manifest, to the `canary` ring first.
3. Promote it to `early` and then `general` after a soak.
4. To withdraw a release, delete its manifest; agents treat a 404 as "no update".

The update key is separate from the grant issuer key. Never reuse one as the other.

**Managed installer** (the **Deploy** page's download button) is opt-in:
1. Put the build kit's output (`DeskRallySetup.exe`, `DeskRallyAgent.msi`, `DeskRallySupport.exe` and
   `installer-manifest.json`) in a directory of its own on the server.
2. Set `MANAGED_INSTALL_HOST_DIR=/srv/deskrally/installers/<release>`.
3. Set `CP_MANAGED_INSTALL_CONTROL_PLANE_URL=https://remote.example.com/cp`.
4. Add `-f deploy/docker-compose.installer.yml` to **every** deploy and rollback command.

The control plane refuses to start if the manifest's URLs, key or hashes do not exactly match its
own configuration, and logs only `managed installer release validation failed`, so check them
carefully. To switch releases, point at a new directory and recreate the control plane; never
edit files in place.

## 6. Backups and restore

A daily user-level systemd timer dumps the database:
```bash
mkdir -p ~/.config/systemd/user
cp deploy/bridge-backup.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now bridge-backup.timer
loginctl enable-linger "$USER"       # required, or the timer stops when you log out
systemctl --user list-timers bridge-backup.timer
```
- **Backups are age-encrypted and REQUIRE a recipient** (`BRIDGE_BACKUP_AGE_RECIPIENT=age1...`, your public key; the private key stays off the server). See [encryption and key management](../22-backup-and-restore.md#7-encryption-and-key-management): without it the script refuses to run.
- Defaults: repository at `~/rmt2`, dumps in `~/bridge-backups`, 14 kept. Override them with
  `BRIDGE_REPO_DIR`, `BRIDGE_BACKUP_DIR` and `BRIDGE_BACKUP_KEEP`.
- **A backup is the dump plus `deploy/.env`.** Without the same `GRANT_ISSUER_SEED`, every
  enrolled agent rejects sessions. Keep a copy of both off the host.
- Include the persistent directive-signing seed, TOTP key and, if central recording is enabled,
  the recording blobs and complete required keyring. Follow the [full recovery-state checklist](../22-backup-and-restore.md#0-the-database-is-not-the-whole-state).
- Never dump with `--no-privileges`: the restored database would lack the grants the control
  plane needs, and it would refuse to start.

**Rehearse a restore** into a scratch database:
1. Create `restore_check`.
2. Load the dump:
   ```bash
   age -d -i ~/age-backup-key.txt <dump>.sql.gz.age | gunzip -c | dc exec -T postgres psql -U rmt -d restore_check
   ```
3. Compare its row counts against the live database.

**Real restore:**
1. `dc down` (**never `dc down -v`**, which deletes the database volume).
2. `dc up -d postgres`.
3. Load the dump into `rmt`.
4. `dc up -d`.

## 7. Upgrading

Production follows a `deploy` git tag:
```bash
git fetch && git tag -f deploy <commit> && git push -f origin deploy
```

On the live server a host script (`~/bin/auto-deploy.sh`, not in the repository) does the rest:
1. checks out the tag;
2. rebuilds the console bundle;
3. runs `dc up -d --build`.

It **holds** a release that adds database migrations until an operator runs it with
`--allow-migrations`.

Without that script, upgrade by hand:
```bash
git checkout <commit>
(cd web/viewer && npm ci && npm run build) && cp -r web/viewer/dist/* dist/viewer/ && cp dist/viewer/index.html dist/viewer/join.html
dc up -d --build
```

- **Rollback** is moving the tag back to the previous commit. Schema changes are never rolled
  back, so read a release's migrations before deploying it.
- The console and the API move together. Users get the new console on their next page load.

## 8. Health, logs and abuse protection

**Health:** `curl -s https://remote.example.com/cp/healthz` prints `ok`. Every container also has
its own health check, so `dc ps` shows `healthy`.

**Logs.**
- `dc logs -f <service>`. Each service keeps 3 × 10 MB.
- Caddy's access log is `/var/lib/docker/volumes/deploy_caddydata/_data/access.log`.
- Validate the Caddyfile before reloading it:
  `dc exec caddy caddy validate --config /etc/caddy/Caddyfile`. A parse error takes the whole site
  down.

**TURN check.** In a browser session, the connection diagnostics should show a relay candidate on
IP-B. The coturn container keeps using its old certificate after Caddy renews it (about every 60
days) until coturn is restarted, so restart coturn after renewals.

**fail2ban** watches `/download` for scraping:
1. `sudo cp deploy/fail2ban/deskrally-download.conf /etc/fail2ban/filter.d/`
2. Append `deploy/fail2ban/jail.local.example` to `/etc/fail2ban/jail.local`.
3. Set its `logpath` to the Caddy access log.
4. `sudo fail2ban-client reload`

Caddy already answers scanner probes with 404, and answers the control plane's internal service
routes (`/cp/internal/*`) with 404.

## 9. Common problems

| Symptom | Cause |
|---|---|
| Ports 5432/8081 reachable from outside | Compose older than 2.24.4, or the base compose file used alone. |
| Every session refused after a rebuild | `GRANT_ISSUER_SEED` empty or changed. Restore the original value from your backup. |
| Signaling restarts in a loop | `CP_DEVICE_IDENTITY_TOKEN` missing or shorter than 32 characters. |
| Control plane exits with `cannot read throttle_counter` | The database was restored from a dump taken with `--no-privileges`. |
| Sessions work on the LAN but not over the internet | TURN not configured, or IP-B port forwards missing. |
| TURNS stops working ~60 days in | coturn still holds the expired certificate; restart coturn. |
| `/download/...` returns 404 | The file is not on the allow-list path, or Caddy was created before the file existed (`--force-recreate caddy`). |
| Microsoft sign-in settings missing | `TOTP_ENCRYPTION_KEY` or `CP_TENANT_HOST_SUFFIX` not set. |
