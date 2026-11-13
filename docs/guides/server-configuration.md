# Server configuration reference

This reference explains how configuration connects the control plane, signaling, PostgreSQL, the HTTPS proxy and TURN. The complete checked-in Compose environment template appears at the end of this page, including its comments and optional settings.

Use the [Docker installation guide](server-deployment.md) or [native Windows/Linux guide](native-server.md) for installation order. The [full build and deployment reference](../10-deployment.md) covers source builds, native codec prerequisites, agent enrollment and the transport design.

## Where configuration is read

Docker installations use deploy/.env with the Compose files in deploy. Run Compose from that directory, or explicitly select the matching environment file. Compose substitutes variables from that file and passes the process variables declared by each service. Merely adding an arbitrary variable to deploy/.env does not guarantee it reaches a process.

Native installations use config/controlplane.env, config/signaling.env, config/relay.env and config/caddy.env in the extracted native package. The launchers read literal KEY=value lines. They do not execute shell commands, expand variables or strip quotes. Do not copy shell expressions such as $(openssl rand -hex 32) into those files: generate a value first and paste the resulting hexadecimal string.

The Compose template below uses deployment variables such as TURN_URLS; native signaling reads process names such as SIGNALING_TURN_URLS. Choose the correct names for your installation. Files containing actual keys and passwords belong outside viewer, download and source control.

## Database owner and application role

| Setting | Used by | Required relationship |
|---|---|---|
| MIGRATE_DATABASE_URL | controlplane migrate | Connect as the schema owner/admin to apply DDL. Do not give this connection to the serving application. |
| APP_DB_PASSWORD | Migration/provisioning command | Sets the password for the separate rmt_app role. |
| DATABASE_URL | Serving control plane | Connect as rmt_app, a non-owner, non-superuser role without BYPASSRLS. |
| POSTGRES_USER / POSTGRES_PASSWORD | Compose PostgreSQL administration | Owner credentials for provisioning and backups; these are not application credentials. |

Tenant isolation depends on row-level security. A superuser or BYPASSRLS role bypasses that protection. Production startup refuses a privileged application connection unless an insecure override is deliberately enabled. Keep CP_INSECURE_ALLOW_PRIVILEGED_DB, CP_INSECURE_DEV and CP_INSECURE_DEV_LISTEN_ANY unset for deployed servers.

The supported migration runner records filenames and checksums in schema_migration. Apply all migrations shipped with the selected server release; do not maintain a handwritten list or silently baseline a database whose schema has not been verified. See [database setup](../10-deployment.md#3a-native-three-servers-postgres).

## Persistent signing and encryption keys

| Setting | Purpose | Consequence of changing or losing it |
|---|---|---|
| GRANT_ISSUER_SEED | Stable Ed25519 grant issuer, 32 bytes encoded as 64 hexadecimal characters | Enrolled agents pin its public key; changing it breaks that trust relationship. |
| DIRECTIVE_SIGNING_SEED | Separate fleet-directive signing key | Agents pin this public key too. Keep it stable and separate from the grant seed. |
| TOTP_ENCRYPTION_KEY | Encrypts stored authenticator secrets | Existing encrypted secrets require the original key or an intentional re-encryption procedure. |
| RECORDING_MASTER_KEY | Wraps central recording data keys | Losing a required master-key version makes those stored recordings unreadable. |
| RECORDING_MASTER_KEY_ID / RECORDING_MASTER_KEY_PREVIOUS | Identifies the current key and retained previous versions | Previous keys use id:hexkey entries separated by commas; preserve versions needed by recordings and backups. |

Generate each key independently and store it persistently. Do not regenerate keys during container or service startup. The public grant key printed at control-plane startup is copied into SIGNALING_TICKET_PUBKEY; the private GRANT_ISSUER_SEED must never be supplied in its place. Keep an encrypted backup of all required keys, separately from the server. See the [backup and restore runbook](../22-backup-and-restore.md#0-the-database-is-not-the-whole-state).

## Service-to-service credentials

| Control-plane setting | Signaling setting | Purpose |
|---|---|---|
| CP_DEVICE_IDENTITY_TOKEN | SIGNALING_DEVICE_IDENTITY_TOKEN | Matching random secret, at least 32 characters, for agent identity verification and internal directive notification. |
| CP_PRESENCE_TOKEN | SIGNALING_PRESENCE_TOKEN | Matching random secret, at least 32 characters, for online-machine presence. |
| CP_PRESENCE_URL | Internal signaling base plus /internal/presence | The private feed polled by the control plane. |
| CP_SIGNALING_NOTIFY_URL | Internal signaling base, no /ws suffix | Optional immediate directive notification; otherwise a directive waits for the agent's next registration. |
| Not applicable | SIGNALING_DEVICE_IDENTITY_URL | Internal control-plane base URL used by signaling; it is not the public /ws endpoint. |

For native processes on one host, internal URLs normally use 127.0.0.1 and ports 8080/8081. Inside Compose, use service names such as signaling and controlplane. Those names are not public DNS names and cannot be handed to remote browsers or agents. Rotate each paired credential on both services together.

## Public addresses, proxy routes and client IPs

| Setting or route | Meaning |
|---|---|
| SITE_ADDRESS | Hostname served by the HTTPS proxy, for example remote.example.com. DNS must already reach that proxy. |
| CP_SIGNALING_URL | Public browser/agent address, for example wss://remote.example.com/ws. |
| CP_PUBLIC_ORIGIN | Public HTTPS origin for recording-upload signatures, scheme and host only, without /cp or another path. |
| SIGNALING_ALLOWED_ORIGINS | Exact allowed browser origins, including scheme and any nonstandard port. |
| CP_TRUSTED_PROXIES / SIGNALING_TRUSTED_PROXIES | CIDR lists of actual proxy peers allowed to supply forwarded client addresses. |
| /cp/* | Proxy to the control plane after stripping /cp. |
| /cp/internal and /cp/internal/* | Refuse publicly with 404; service calls use the private control-plane listener. |
| /ws | WebSocket proxy to signaling. |
| /download/* | Published artifacts; a missing executable must return 404, not the SPA HTML. |

For a same-host native proxy, 127.0.0.1/32 and ::1/128 describe loopback proxy peers. For Compose, use the actual trusted container-network CIDR. Avoid trusting an entire private address range simply because it is convenient. CP_TRUST_PROXY_IP=1 is the legacy mode and accepts forwarded address information from any peer that can reach the application; explicit proxy CIDRs are preferable. The same address derivation affects access restrictions, throttling and audit source addresses.

Bind native control-plane/signaling listeners to loopback unless a private multi-host topology requires another address. Do not publish PostgreSQL or raw backend ports to the internet. HTTPS terminates at the proxy; the browser console and signaling address must use compatible secure origins. See [proxy source-address behavior](../10-deployment.md#3a-ii-client-source-address-audit-trail-and-the-proxy-trust-settings).

## TURN settings and credential limits

| Compose deployment name | Native signaling process name | Purpose |
|---|---|---|
| STUN_URLS | SIGNALING_STUN_URLS | Public STUN URL list. |
| TURN_URLS | SIGNALING_TURN_URLS | Comma-separated public TURN URLs, including TCP/TLS where needed. |
| TURN_SHARED_SECRET | SIGNALING_TURN_SECRET | Must match coturn's static authentication secret. |
| TURN_TTL | SIGNALING_TURN_TTL | Short-lived credential lifetime; current source default is 2h. |
| TURN_MAX_PER_USER | SIGNALING_TURN_MAX_PER_USER | Outstanding credentials per technician; current source default is 20. |
| TURN_MAX_PER_TENANT | SIGNALING_TURN_MAX_PER_TENANT | Outstanding credentials per tenant; current source default is 80. |

Credentials count against their limits until they expire, even if a session ends. Repeated reconnects can exhaust a limit. Public TURN URLs must be reachable by the peers; a container name such as coturn is not suitable. Supplying TURN URLs without a matching secret leaves TURN unavailable. The raw DeskRally relay is a different protocol and cannot replace TURN.

For certificate synchronization, allocation ranges and TURN on restrictive networks, see [the TURN reference](../10-deployment.md#6-enabling-turn-for-wan). For the user-facing relay-limit notice and evidence to collect, see [connection troubleshooting](../connection-troubleshooting.md#no-relay-connection-is-available).

## Recording storage and writable data

Central recording is enabled only when the release supports it and RECORDING_MASTER_KEY is configured. Set RECORDING_DIR to a real directory outside the web roots, writable by the control-plane service identity. The root must not be a symlink or Windows junction, and .incoming/.quarantine must remain on the same filesystem.

On Windows, explicitly select a path such as C:/ProgramData/DeskRally/recordings before enabling the master key; the default /var/lib/deskrally/recordings is a Linux path. On Linux systemd, add the directory to ReadWritePaths when using the read-only service template. Container installs must persist the configured storage on a volume rather than rely on the container's writable layer. Check the release's actual volume and variable wiring before enabling storage.

Set the tenant retention policy deliberately; it defaults off. Back up the complete required keyring (the current key plus every _PREVIOUS entry): losing it makes the recordings unreadable. Retention is a deletion policy, not durability, so the recording volume is outside the v1 backup contract and is covered only by operator-owned tooling (see [backup and restore](../22-backup-and-restore.md)). RECORDING_RECONCILE_MODE is for the restore drill (it enables the `lost` marking pass; docs/22 section 4 has the exact steps), not an everyday startup setting. RECORDING_DISK_FLOOR_MIB (default 5120 = 5 GiB, valid 512 to 1048576; an invalid value stops startup) is the free-space floor below which new uploads are refused; the volume often shares a filesystem with Postgres, so keep it generous. See [recording storage and rotation](native-server.md#recording-storage-and-key-rotation) and [backup and restore](../22-backup-and-restore.md).
