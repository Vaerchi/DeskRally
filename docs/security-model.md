# DeskRally security model

DeskRally gives a technician control of another person's computer. On computers with the permanent agent, that
control can run as SYSTEM. This page summarises how the product limits who can do that, what is recorded, and
how releases are trusted. It also lists the limits that apply today. To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

The design reasoning lives in [02-architecture.md](02-architecture.md). This page describes what the code does
now, not the target design.

## Components

- **Control plane** (Go, PostgreSQL). Handles accounts, tenants, machines, permissions, the audit record, and
  signing access grants.
- **Signaling** (Go). Brokers the WebRTC connection between a technician and a machine.
- **Agent** (Rust, Windows). Has two parts:
  - a service that runs as SYSTEM;
  - a helper that runs in each interactive Windows session and handles capture and input.
- **Console** (TypeScript, browser). The technician's interface.
- **Support client** (`DeskRallySupport.exe`). A temporary client for one attended session that needs no install.
- **TURN** (coturn, optional). Relays connections that cannot go peer-to-peer.

## Tenant isolation

- All tenants share one PostgreSQL schema. Each tenant-scoped table carries a `tenant_id`.
- Isolation is enforced by PostgreSQL row-level security, with `FORCE ROW LEVEL SECURITY` set. Each request sets
  its tenant before it touches data. The application connects as a role that cannot bypass the policies, so a
  missing filter in application code does not expose another tenant's rows.
- Composite foreign keys tie related rows to the same tenant. Without them, a write could reference a row in
  another tenant even though reads are filtered.
- A self-hosted deployment is one tenant on the same code path. There is no separate single-tenant mode to drift.

## Accounts and sign-in

- **Passwords** are hashed with Argon2id.
- **Two-factor sign-in** uses authenticator apps (TOTP). The secrets are stored encrypted with a key held in the
  server's configuration.
- **Single sign-on** with Microsoft Entra ID (OIDC) is supported ([34-console-sso.md](34-console-sso.md)).
- **Console sessions** use an `HttpOnly`, `SameSite=Lax` cookie. State-changing requests also need a
  double-submit CSRF token.
- **Repeated failed sign-ins** lock the account for a period, and sign-in requests are rate-limited.
- **Credential changes.** Each console session records the credential version it was signed in with. A password or
  email change advances that version, so every older console session is refused, including one signed in at the
  moment of the change.
- **Permission changes.** Permissions are read from the database on every console request, so a role or group change
  applies to the console at once.
- **Permissions** are role-based and scoped to the tenant, or to groups and subgroups of machines
  ([62-subgroups.md](62-subgroups.md)).
- **Time-limited access.** Access can expire, or be limited to scheduled windows
  ([56-expiring-access.md](56-expiring-access.md), [57-scheduled-access-windows.md](57-scheduled-access-windows.md)).

## Machines and the agent

- **Agent identity.** Each agent enrolls with a single-use enrollment token. It then authenticates to the
  server with its own device credential.
- **Signed grants.** A technician's action on a machine needs more than a signed-in console. The agent only
  acts on an access grant that the control plane signs with its Ed25519 issuer key. The agent checks each grant
  against the pinned issuer key, its validity window and the agent's own machine ID before acting. This applies
  to Backstage (the remote tools that work without taking over the screen), file transfer, elevation and
  command runs. A grant made for one machine is refused by every other machine.
- **Riskier actions need a stronger grant.** Opening a SYSTEM shell needs its own grant: consent to being
  viewed is not consent to a SYSTEM shell. Terminating protected system processes is refused outright.
- **File transfer** is limited to the paths and direction the grant allows.
- **Windows privileges.** The SYSTEM service and the per-session helper are separate processes. The elevation
  pipe refuses remote clients and checks which process has connected.

## Consent and visibility

- **Attended support sessions** start only after the person at the computer accepts a consent prompt. An
  on-screen indicator stays visible for the whole session, and they can end it at any time
  ([12-attended-sessions-contract.md](12-attended-sessions-contract.md)).
- **Raising an attended session to administrator** needs the user's own Windows elevation consent
  ([53-attended-elevation.md](53-attended-elevation.md)).
- **Unattended access** to a computer with the permanent agent is controlled by the tenant's permissions and
  access policies. Every unattended connection is recorded in the audit log.

## Audit trail

- Every significant action is recorded per tenant: sign-ins, permission changes, sessions, Backstage actions,
  file transfers and command runs.
- Session tool actions are written into a hash chain. Each event includes the SHA-256 hash of the event before
  it, and the control plane refuses any addition that does not continue the stored chain. If a stored record
  is edited or removed, the chain no longer verifies.

## Network and transport

- **Session traffic** (screen, input, files, Backstage) travels over WebRTC, encrypted with DTLS between the
  technician's browser or client and the agent.
- **TURN.** A TURN relay forwards the encrypted packets and cannot read them. Relay credentials are short-lived
  HMAC credentials (`--use-auth-secret`). The shipped TURN configuration refuses to relay to private and
  loopback address ranges, so the relay cannot be used to reach the server's internal network.
- **Web traffic.** The web front end uses HTTPS with HSTS. Framing is denied, through `frame-ancestors 'none'`
  and `X-Frame-Options`.
- **Content Security Policy.** It currently runs in report-only mode. Violations are collected at
  `/cp/csp-report` with bounded, redacted logging, so the policy can be tightened before it is enforced.

## Updates and releases

- **Agent releases** are delivered as an MSI and described by an update manifest. The manifest is signed with
  Ed25519.
- **Before installing an update, the agent checks:**
  - the manifest signature against a pinned key;
  - the release hash;
  - the MSI's Authenticode publisher;
  - the expected version;
  - that the install path is the expected one and its file permissions are safe.

  It refuses the update if any of these fail ([agent-update.md](agent-update.md)).
- **Builds from source** do not trust the project's official update feed unless they are built with it
  explicitly turned on (`DESKRALLY_UPDATE_OFFICIAL=1`). A self-built agent therefore never installs updates
  signed by someone else.
- **Licensing.** The MSI includes the licence, the notice and the licence texts of all third-party code it ships.

## Known limits

- **Not end-to-end against the brokering server.** Session traffic is encrypted between the two ends, but the
  DTLS fingerprints are exchanged through signaling and are not yet pinned to long-term device keys. Someone in
  control of the signaling server could therefore intercept a session. The design to close this gap is in
  [02-architecture.md](02-architecture.md) (ADR-004) and is not yet shipped. Treat the server as part of your
  trusted base.
- **The Content Security Policy is not yet enforced** (see above).
- **Live sessions outlast a permission change.** If a technician's role or group scope is reduced, a remote-control
  session they already have open continues until it ends. To cut one off at once, end that session from the Machines
  list.
- **Platform.** Only Windows has an agent. macOS and Linux agents are not available.
- **Your deployment.** A deployment's security also depends on its configuration, its updates and how it is
  run. This page is not a certification.

## How it is tested

- **No-skip verification.** `scripts/verify-all.ps1` runs every suite: Rust, Go, the console and the
  cross-language end-to-end tests. It treats a skipped test as a failure, so a missing prerequisite cannot turn
  into a silent pass.
- **Real database.** Row-level security and permission tests run against a real PostgreSQL server, connected
  as the application's own restricted role.
- **Shared test vectors.** Grant and manifest signatures use the same test vectors in the Go signer and the
  Rust verifier.
- **Real Windows.** Releases are tested on Windows virtual machines, with the agent installed, upgraded and
  driven, including the secure desktop and attended consent.
- **Independent review.** Security-relevant changes are reviewed independently before release. The project
  runs recurring security audits from an unauthenticated internet attacker's point of view.
