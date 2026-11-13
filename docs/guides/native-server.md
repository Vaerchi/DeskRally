# Run DeskRally without Docker

Run the DeskRally control plane, signaling server and relay as native programs on Windows or Linux. PostgreSQL and your HTTPS proxy can run on the same machine or on separate servers. Docker remains an alternative installation method.

For deeper reference, read the [source-build and deployment documentation](../10-deployment.md),
[configuration variables and complete environment template](server-configuration.md),
[backup and restore runbook](../22-backup-and-restore.md), and
[connection diagnostics](../connection-troubleshooting.md). These are the detailed references behind this installation path.

## Deployment status

Native deployment is a preview installation path. Build and launcher checks do not prove a production deployment. A fresh Windows service installation, a fresh Linux systemd installation, reboot recovery and a complete remote session must pass acceptance before this path is described as production-tested. The existing Docker release remains the established deployment path.

Validate migrations, first-administrator creation, separate service identities, installation-directory
permissions, database listen addresses and the verification list below. Test reboot recovery and a
complete browser session to an enrolled computer on your target operating system. Windows Server
editions require separate acceptance.

The server operating system does not change agent support: the managed computers currently use the Windows agent. A Windows server does not need Docker Desktop, WSL or a Linux virtual machine to run the DeskRally services.

## Choose an installation

- Docker on Linux: use the existing server installation guide and release installer.
- Native Linux: unpack native binaries, install PostgreSQL and Caddy, then use systemd to keep the services running.
- Native Windows: unpack native binaries, install PostgreSQL, Caddy and PowerShell 7, then use a service wrapper to keep the services running.

Native archives are built from the source checkout. They are not yet advertised as downloadable public releases. Do not substitute the Docker archive for a native archive.

## What you need

- A dedicated Windows or Linux host, with administrator access for installation. The default native build targets x64; ARM64 builds are optional and need their own acceptance checks.
- PostgreSQL 16, running locally or reachable privately. The server needs the standard PostgreSQL extensions supplied with that installation. Keep port 5432 private.
- A DNS hostname, such as remote.example.com, pointing at the HTTPS proxy. Open TCP 80 and 443 to that proxy. HTTPS is required for remote browser access.
- Caddy installed from its official distribution, or another reverse proxy configured with the same routes. The package does not download or bundle third-party services.
- A TURN service for reliable connections between different networks. A Windows DeskRally host can use TURN on a separate Linux machine or a managed TURN service supporting shared-secret, time-limited credentials. TURN is independent of the native DeskRally processes.
- PowerShell 7 on Windows. Linux uses its existing POSIX shell; PowerShell is needed only if you build the packages there.

DeskRally currently uses one signaling instance. Moving the database or TURN to another machine does not make signaling highly available; its live connection registry remains in memory.

## Build a native package

On the build computer, install Git, PowerShell 7, a Go toolchain satisfying the checked-in go.mod files, and a Node version satisfying web/viewer/package.json. A C compiler is not required for these server binaries. Run from the repository root:

```powershell
pwsh -File scripts/package-native-server.ps1
```

This builds both x64 targets into dist/native-server, including the console, SQL migrations, configuration examples and launchers. Windows uses ZIP and Linux uses tar.gz. Each archive has a SHA-256 sidecar. Use a new output directory for each rebuild; the packager refuses to overwrite an existing staging directory.

```powershell
pwsh -File scripts/package-native-server.ps1 -Platform windows -OutputDirectory dist/native-win
pwsh -File scripts/package-native-server.ps1 -Platform linux -Architecture arm64 -OutputDirectory dist/native-linux-arm64
```

Go and Node are build dependencies only. The installed server runs the compiled binaries and static console. Check each archive's SHA-256 against a value obtained from your trusted build or release channel before extracting it.

## Unpack and configure

Extract the package into C:/DeskRally on Windows, or /opt/deskrally on Linux. Move the contents of the archive's top-level directory there so that bin, viewer, migrations and config are directly inside the installation directory.

Copy each config/*.env.example file to the same name without .example. Each process reads only its own file. Use literal KEY=value lines: no quotes, export statements, variable references or command substitutions. A value may contain equals signs. Comments must start with #. These files contain secrets; keep them outside viewer and download, and restrict access to the administrator and the service identity.

Generate independent random values for the grant issuer seed, directive signing seed, TOTP encryption key, device identity token and presence token. Each can be 32 random bytes encoded as 64 hexadecimal characters. Keep the signing seeds and TOTP key stable across upgrades and back them up securely. In the upcoming fleet-directive release, DIRECTIVE_SIGNING_SEED is separate from GRANT_ISSUER_SEED: agents pin its public key at enrollment for fleet removal/reinstall directives. Never regenerate either seed on startup.

For that fleet release, CP_SIGNALING_NOTIFY_URL is the signaling server's internal base URL, normally http://127.0.0.1:8080. It enables immediate directive notifications using CP_DEVICE_IDENTITY_TOKEN, which must match SIGNALING_DEVICE_IDENTITY_TOKEN. Without this optional URL, directives wait for the agent's next registration. It is meaningful only when DIRECTIVE_SIGNING_SEED is configured. Do not expose the internal notification route through the public proxy.

```powershell
[Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
```

On Linux, openssl rand -hex 32 produces the same format. Run it separately for each secret.

In controlplane.env, replace the database password and hostname, the signing/encryption keys, CP_SIGNALING_URL and both service tokens. In signaling.env, copy the matching device and presence tokens. Set SIGNALING_ALLOWED_ORIGINS to your exact HTTPS origin. Keep the internal URLs pointing to loopback when everything runs on one host.

In caddy.env, set SITE_ADDRESS, VIEWER_ROOT and DOWNLOAD_ROOT. Windows paths must use forward slashes, for example C:/DeskRally/viewer. The download directory ships with only agent/new-msi-provisioning.ps1 and its .sha256.txt, which the client guide's MSI install fetches from your server. Other download artifacts are optional, and missing downloads return 404. Creating a server does not automatically provide deployment-specific agent installers.

## Create the database and apply migrations

Using your PostgreSQL administration tool, create an empty database named rmt. Keep the owner/admin credential separate from the application's credential. The migration command creates the least-privilege rmt_app role; APP_DB_PASSWORD sets its password. Do not run the application as the database owner or disable its privileged-role startup check.

The owner connection (MIGRATE_DATABASE_URL) must be a PostgreSQL **superuser**, such as the built-in postgres role with a password set. The migrations write to tables that enforce row-level security, and they set rmt_app's role attributes, so a role with only CREATEROLE or BYPASSRLS is refused. Use this credential only for migrations and the first-administrator command. The services never use it. On Ubuntu, for example:

```bash
sudo -u postgres psql -c "ALTER ROLE postgres PASSWORD 'choose-a-long-random-password'" -c "CREATE DATABASE rmt"
```

On Windows, open PowerShell 7 in C:/DeskRally:

```powershell
$env:MIGRATE_DATABASE_URL = Read-Host 'Owner PostgreSQL connection URL'
$env:APP_DB_PASSWORD = Read-Host 'New rmt_app password' -MaskInput
.\run-service.ps1 controlplane migrate --dir .\migrations
Remove-Item Env:MIGRATE_DATABASE_URL, Env:APP_DB_PASSWORD
```

On Linux, use Bash in /opt/deskrally:

```bash
read -r -s -p 'Owner PostgreSQL connection URL: ' MIGRATE_DATABASE_URL; echo
read -r -s -p 'New rmt_app password: ' APP_DB_PASSWORD; echo
export MIGRATE_DATABASE_URL APP_DB_PASSWORD
sh ./run-service.sh controlplane migrate --dir ./migrations
unset MIGRATE_DATABASE_URL APP_DB_PASSWORD
```

Check the migration exit status and output before continuing. Set DATABASE_URL in controlplane.env to connect as rmt_app with that password. URL-encode special characters in the password when placing it inside a PostgreSQL URL. The sample sslmode=disable is for loopback only; use verified database TLS when connecting across machines.

## Create the first administrator

Run once, after successful migration. Choose a tenant slug and keep it for sign-in. This example uses main. Only the owner connection may create a tenant, so set MIGRATE_DATABASE_URL again for this one command:

```powershell
$env:MIGRATE_DATABASE_URL = Read-Host 'Owner PostgreSQL connection URL'
.\run-service.ps1 controlplane bootstrap --tenant main --name "Example Company" --email admin@example.com
Remove-Item Env:MIGRATE_DATABASE_URL
```

```bash
read -r -s -p 'Owner PostgreSQL connection URL: ' MIGRATE_DATABASE_URL; echo
export MIGRATE_DATABASE_URL
sh ./run-service.sh controlplane bootstrap --tenant main --name 'Example Company' --email admin@example.com
unset MIGRATE_DATABASE_URL
```

The command prints a generated password once. Save it privately, sign in with the tenant slug and email, then change the password and enroll an authenticator. A repeated bootstrap reports an error when an owner already exists; it does not reset that account.

## Start the services in the foreground

Start the control plane first. Read grant_issuer_pubkey from its startup log and copy the 64-character public key into SIGNALING_TICKET_PUBKEY in signaling.env. This is the public key, not GRANT_ISSUER_SEED. Then start signaling and, if required, the raw relay in separate terminals.

```powershell
.\run-service.ps1 controlplane
.\run-service.ps1 signaling
.\run-service.ps1 relay
```

```bash
sh ./run-service.sh controlplane
sh ./run-service.sh signaling
sh ./run-service.sh relay
```

Run each command in its own terminal. Ctrl+C stops that process. The launchers bind DeskRally listeners to loopback. The raw relay is optional for the browser/WebRTC path and is not a substitute for TURN; the supplied configuration keeps it private.

Install the official Caddy binary into bin/caddy.exe on Windows or bin/caddy on Linux. On Linux, ensure the binaries are executable with chmod +x bin/*. Run the proxy as a service as described below; do not run all DeskRally processes as administrator just to bind HTTPS ports.

The supplied native Caddyfile serves the console, public documentation and downloads; strips /cp before forwarding to the control plane; proxies /ws to signaling; and denies /cp/internal routes. If you use another proxy, preserve these behaviors. Never publish 8080, 8081, 9000, 9001 or 5432 directly.

## Keep Linux services running

Run each service as its OWN system account. Signaling is the internet-facing process and holds the least; if it were compromised it must not be able to read the control plane's secrets (grant issuer seed, directive signing seed, TOTP key, recording master key, database password). The unit template picks the account from the instance name: `deskrally@controlplane` runs as `deskrally-controlplane`, `deskrally@signaling` as `deskrally-signaling`, `deskrally@relay` as `deskrally-relay`. Keep application code owned by root and give each config file to exactly one service group. Caddy uses the account of its own package and is not run from this template. For a new installation:

```bash
for s in controlplane signaling relay; do
  sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin "deskrally-$s"
done
sudo chown -R root:root /opt/deskrally
sudo chmod 755 /opt/deskrally /opt/deskrally/bin
sudo chmod 755 /opt/deskrally/bin/*
# config dir: traversable but not listable; each file readable only by its own service
sudo chmod 711 /opt/deskrally/config
for s in controlplane signaling relay; do
  sudo chown "root:deskrally-$s" "/opt/deskrally/config/$s.env"
  sudo chmod 640 "/opt/deskrally/config/$s.env"
done
# caddy.env is read by Caddy's own service account (for example: chown root:caddy, chmod 640)
sudo cp /opt/deskrally/deskrally@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now deskrally@controlplane deskrally@signaling
sudo systemctl status deskrally@controlplane deskrally@signaling
```

These commands assume a distribution with systemd and useradd; adapt account creation to your distribution. Enable deskrally@relay only if you need the private raw relay. Read logs with journalctl -u deskrally@controlplane -u deskrally@signaling. Stop the foreground processes before starting service instances.

Shared secrets, listed explicitly. Only these values legitimately appear in more than one service's file, so a compromise of one process exposes nothing else:

| Value | controlplane.env | signaling.env | Sensitivity |
|---|---|---|---|
| Device identity token | `CP_DEVICE_IDENTITY_TOKEN` | `SIGNALING_DEVICE_IDENTITY_TOKEN` | Lets the holder query device identities; rotate if signaling is compromised |
| Presence token | `CP_PRESENCE_TOKEN` | `SIGNALING_PRESENCE_TOKEN` | Lets the holder read the presence feed |
| Grant issuer PUBLIC key | (derived at startup) | `SIGNALING_TICKET_PUBKEY` | Public |

Everything else stays in exactly one file: the grant issuer seed, directive signing seed, TOTP key, recording master key and database URL belong only in controlplane.env; the TURN secret belongs only in signaling.env. Never copy those into another service's file.

Run Caddy using its official Linux service installation, with permission to bind 80/443 and persistent storage for certificates. Set SITE_ADDRESS, VIEWER_ROOT and DOWNLOAD_ROOT in its systemd environment, point its ExecStart at /opt/deskrally/Caddyfile, and grant the caddy identity read access to viewer and download only. Do not use the hardened DeskRally template for Caddy; it needs certificate storage and HTTPS port access. With Caddy's official Debian/Ubuntu package (service caddy, user caddy), a drop-in does all of this:

```bash
sudo chown root:caddy /opt/deskrally/config/caddy.env && sudo chmod 640 /opt/deskrally/config/caddy.env
sudo mkdir -p /etc/systemd/system/caddy.service.d
sudo tee /etc/systemd/system/caddy.service.d/deskrally.conf >/dev/null <<'EOF'
[Service]
EnvironmentFile=/opt/deskrally/config/caddy.env
ExecStart=
ExecStart=/usr/bin/caddy run --environ --config /opt/deskrally/Caddyfile --adapter caddyfile
ExecReload=
ExecReload=/usr/bin/caddy reload --config /opt/deskrally/Caddyfile --adapter caddyfile --force
EOF
sudo systemctl daemon-reload && sudo systemctl restart caddy
```

In that case the Caddy binary comes from the package (/usr/bin/caddy), so nothing goes in bin/.

The DeskRally unit has a read-only filesystem. If you enable features that write to disk, provision a separate data directory and explicitly add ReadWritePaths for it in a systemd override. PostgreSQL, Caddy and TURN have their own service lifecycle and backups.

## Keep Windows services running

The Go programs are console executables, so pointing sc.exe directly at controlplane.exe will not provide the Windows service protocol. Use WinSW as the service wrapper. Install PowerShell 7 and obtain WinSW from its official project. Keep the wrapper and configuration in the package root, separate from the DeskRally binaries in bin.

Copy windows-service.xml.example to deskrally-controlplane.xml, and copy the WinSW executable to deskrally-controlplane.exe. Repeat for signaling, changing the XML id to DeskRallySignaling, name to DeskRally Signaling, the -Service argument to signaling and the logpath folder to signaling. Do the same for Caddy (DeskRallyCaddy, -Service caddy). Each service needs its own wrapper filename and matching XML filename. Repeat for relay only if needed.

In an elevated PowerShell terminal, install the configured wrappers. Start them only after the accounts and permissions below are in place:

```powershell
.\deskrally-controlplane.exe install
.\deskrally-signaling.exe install
.\deskrally-caddy.exe install
```

Give each service its OWN account (for example a separate virtual or managed service account per service, never one shared account and never LocalSystem), mirroring the Linux accounts: the signaling account must not be able to read controlplane.env. Set the ACL on each config*.env file to SYSTEM, Administrators and that one service account only. Configure dedicated service identities using Windows Services or your service-account policy. Before starting, grant those identities read/execute access to the installation and read access to their configuration; remove ordinary users' access to config. Do not leave the wrapper running as LocalSystem merely because that is its default. Verify the PowerShell path in each XML and resolve any execution-policy restrictions using your organization's signing policy.

**Lock the installation folder first.** A folder created directly under C:\ inherits "Authenticated Users: Modify". Left as it is, any local account could replace bin\controlplane.exe, including the internet-facing signaling service's own account. Whoever replaces it runs with the control plane's secrets. Because the services may no longer write there, WinSW's logs go to a per-service folder that only that service can write to. Put a `<logpath>` line in each XML, for example `<logpath>C:\ProgramData\DeskRally\logs\controlplane</logpath>` (the example file shows it). In an elevated PowerShell, with the wrappers installed but not yet started:

```powershell
Set-Location C:\DeskRally
icacls C:\DeskRally /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)RX'
icacls config /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F'
$services = @{ controlplane = 'DeskRallyControlPlane'; signaling = 'DeskRallySignaling'; caddy = 'DeskRallyCaddy' }
foreach ($key in $services.Keys) {
    $id = $services[$key]
    sc.exe config $id obj= "NT SERVICE\$id"                       # a virtual account of its own
    icacls "config\$key.env" /inheritance:r /grant:r 'SYSTEM:F' 'Administrators:F' "NT SERVICE\${id}:R"
    icacls config /grant "NT SERVICE\${id}:(RX)"
    $logs = "C:\ProgramData\DeskRally\logs\$key"
    New-Item -ItemType Directory -Force $logs | Out-Null
    icacls $logs /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' "NT SERVICE\${id}:(OI)(CI)M"
}
New-NetFirewallRule -DisplayName 'DeskRally HTTPS' -Direction Inbound -Protocol TCP -LocalPort 80,443 -Action Allow
.\deskrally-controlplane.exe start
.\deskrally-signaling.exe start
.\deskrally-caddy.exe start
Get-Service DeskRallyControlPlane, DeskRallySignaling, DeskRallyCaddy
```

Run Caddy as a separate Windows service using its official instructions. It may use the same wrapper pattern with -Service caddy, its own config/caddy.env and writable certificate storage for its service identity. Keep that identity and storage stable across restarts. With the virtual account above, Caddy keeps its certificates and its local CA in C:\Windows\ServiceProfiles\DeskRallyCaddy\AppData\Roaming\Caddy. Include that folder in your backups. Check the wrapper logs in C:\ProgramData\DeskRally\logs\<service> when a service fails to start. The services are not ordered after PostgreSQL at boot. If the control plane starts first it exits, and the wrapper's restart policy brings it back once the database is up.

The PostgreSQL Windows installer (EnterpriseDB) listens on every address by default. The Windows Firewall blocks 5432 unless you open it, but set `listen_addresses = 'localhost'` in C:\Program Files\PostgreSQL\16\data\postgresql.conf and restart the postgresql-x64-16 service when everything runs on one host.

## Configure TURN

Set SIGNALING_STUN_URLS and SIGNALING_TURN_URLS to addresses reachable by the agents and browsers. Set SIGNALING_TURN_SECRET to the TURN service's shared authentication secret, then restart signaling. These are signaling process settings, not Docker-specific settings.

For networks that block UDP, provide TURN over TCP and TLS as well. TURN TLS on 443 usually needs its own public address when the website already occupies 443. Open the TURN listener and allocation port range on the TURN host. Use your TURN provider's certificate, public-address and private-network access restrictions; do not expose an unrestricted relay.

## Recording storage and key rotation

Central recording is upcoming; these settings prepare for a recording-enabled release and do not promise availability in the deployed server. Storage is enabled only when RECORDING_MASTER_KEY is set. Set CP_PUBLIC_ORIGIN to the exact public HTTPS origin, such as https://remote.example.com, without a path. It is the recording upload signature audience. The loopback trusted-proxy configuration preserves per-client throttling behind Caddy.

Create RECORDING_DIR outside both web roots. Use a real directory, not a symlink or Windows junction, on a filesystem that also holds its .incoming and .quarantine subdirectories. The control-plane service identity must own and be able to write it. On Linux:

```bash
sudo install -d -o deskrally-controlplane -g deskrally-controlplane -m 700 /var/lib/deskrally/recordings
sudo systemctl edit deskrally@controlplane
```

Add this override and set RECORDING_DIR=/var/lib/deskrally/recordings in controlplane.env:

```ini
[Service]
ReadWritePaths=/var/lib/deskrally/recordings
```

On Windows, create C:/ProgramData/DeskRally/recordings, grant the control-plane service account Modify access, remove ordinary users' access, and explicitly set RECORDING_DIR to that path before setting RECORDING_MASTER_KEY. A blank directory setting defaults to /var/lib/deskrally/recordings, which is the Linux path and must not be relied on for Windows. Keep binaries and configuration read-only to the service. Never place recording data in viewer or download.

Generate another independent 32-byte hexadecimal key for RECORDING_MASTER_KEY and set RECORDING_MASTER_KEY_ID to a positive integer, initially 1. This key is separate from both signing seeds and the TOTP key. Back it up before enabling storage: losing the key makes every recording encrypted under it unreadable. Preserve every older key version still referenced by stored recordings or backups.

For rotation, assign the new current key a new ID and retain the old ID/key in RECORDING_MASTER_KEY_PREVIOUS, whose format is id:hexkey,id:hexkey. Use the recording-enabled release's supported rewrap procedure and verify old and new recordings before removing any old key. Do not assume changing the environment re-encrypts existing recordings. Storage retention starts OFF; enabling storage also requires an explicit tenant recording policy.

Back up the complete keyring (current key plus every _PREVIOUS entry): without it recordings are unreadable. Retention is a deletion policy, not durability, and in v1 the recording directory is OUTSIDE the DeskRally backup contract; a snapshot of it is optional operator tooling. See [backup and restore](../22-backup-and-restore.md) section 4. During restore drills, follow that release's reconcile procedure using RECORDING_RECONCILE_MODE; leave it unset in normal operation. Test a restore in isolation before allowing cleanup or retention jobs to affect restored data.

## Verify before relying on the server

- From the server, request http://127.0.0.1:8081/healthz and http://127.0.0.1:8080/healthz; both should report healthy.
- From another computer, open https://remote.example.com/docs and /console. Check the HTTPS certificate and sign in as the first owner.
- Request /cp/internal/presence publicly; it must return 404. A missing /download/example.exe must also return 404.
- Verify that PostgreSQL and internal DeskRally listener ports cannot be reached externally.
- Publish the correct agent artifacts for this deployment, enroll a Windows computer and complete a browser session. Test from another network and from a network with UDP blocked to exercise TURN.
- Restart each service and reboot the host. Verify service recovery, administrator sign-in, machine presence, reconnect and a new remote session. Restarting signaling interrupts live sessions.
- Restore a database and configuration backup into an isolated environment, then verify sign-in and a session. Do not treat the server as production-tested until these checks pass.

## Updates, backups and recovery

Before upgrading, back up PostgreSQL, the stable GRANT_ISSUER_SEED and DIRECTIVE_SIGNING_SEED, TOTP_ENCRYPTION_KEY, service tokens, configuration, published agent artifacts and proxy certificate storage. If recording storage is enabled, also back up RECORDING_MASTER_KEY (blobs only if you run your own volume snapshots; they are outside the v1 contract), its key ID and every previous key version still needed. Keep backups encrypted and outside the web roots.

Stop DeskRally services, unpack the new release into a separate directory, retain the old binaries, apply the new release's migrations with the owner credential, then update service paths or replace the stopped application files. Preserve config and data; never overwrite them with examples. Restart and repeat health, sign-in, presence and remote-session checks.

Database migrations may make old binaries incompatible. Rollback must use a matching database backup and configuration, not just an old executable. A lost TOTP key prevents decrypting stored authenticator secrets; a changed grant seed invalidates agents' pinned issuer identity.

If controlplane refuses startup, inspect its output for database connectivity, pending migrations or a privileged database role. If signaling refuses startup, check its ticket public key and device-identity token. If the site works but sessions do not connect across networks, check TURN reachability, credentials and firewall rules. If an installer is unavailable, configure and publish deployment-specific agent artifacts separately from the server package.

## Reference projects

- Caddy installation and service setup: https://caddyserver.com/docs/running
- Caddy command-line reference: https://caddyserver.com/docs/command-line
- WinSW service configuration and commands: https://github.com/winsw/winsw

The templates follow those projects' service mechanisms. Their presence in a package does not mean a clean-host service acceptance run has passed.
