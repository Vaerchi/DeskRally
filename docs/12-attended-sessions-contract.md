# Attended (On-Demand) Support Sessions — Implementation Contract (M-ATT)

Implementation contract for four independent implementers, split by directory: **C** (Go
control-plane), **S** (Go signaling), **R** (Rust agent), **W** (web viewer). It is normative.
Where it says MUST, deviating is a bug, not a style choice. Read [§10 Work split](#10-work-split)
before touching a file. Style, posture, and golden-vector discipline follow
[docs/11-agent-identity-contract.md](11-agent-identity-contract.md).

Status: shipped. Attended sessions are implemented across the control plane, signaling server,
agent and web viewer; later sections record amendments made after the first implementation.

---

## 1. The gap

Everything shipped so far is **unattended** access: a machine is enrolled once (server-minted
`device_id`, pinned Ed25519 key, LocalSystem service) and a technician reaches it whenever they hold
a session ticket. That is half of what ScreenConnect is. The other half is **attended / on-demand**:

> A user with a problem right now runs a small one-time client, reads back a code (or clicks a join
> link), sees a consent prompt, and — only after they say yes — a technician can view and control
> their screen, with an on-screen indicator up for the whole session. Nothing is installed; when the
> session ends the client is gone.

The two consent/visibility pieces are **legal**, not cosmetic: a remote-access tool that can attach
without consent and run with no on-screen indicator is a RAT, and both AV vendors and buyers treat
it as one (docs/02 "Trust posture"; ScreenConnect restricted hiding the banner in 2025 to curb
abuse — we match that stance deliberately).

**M-ATT in one sentence:** an attended session is a **consent-gated, time-boxed, ephemeral
enrollment** — the guest client redeems a one-time code for a short-lived server-minted identity,
the user consents, and from there the *exact same* signaling / ticket / WebRTC data plane carries
the session; a "promote" action converts the ephemeral guest into a permanent unattended install by
running the *existing* enrollment machinery.

---

## 2. Design: maximise reuse

The whole point is that attended is **not a second stack**. It reuses, unchanged:

| Concern | Reused mechanism | Change for M-ATT |
|---|---|---|
| Agent proof-of-possession at `register_agent` | `RMTAGENTAUTHv1` (docs/11) | **none** — the guest's ephemeral key is pinned server-side and resolved via the *same* `GET /internal/devices/{id}/identity` |
| Technician authorization to a device | `RMTTICKETv1` session ticket (ticket.go) | **none** — the ticket is minted for the ephemeral `device_id`, bound to tenant, exactly as unattended |
| Rendezvous / brokering | signaling `connect_request` + broker | **none** |
| WebRTC data plane (video/input/files/clipboard) | `serve_session` / `WebRtcTransport` | **none** |
| Backstage authorization | H1 signed grants (`BackstageAuth`, host.rs) | **the trust anchor is delivered differently.** An unattended agent pins `grant_issuer_pubkey` from its config at install time; an attended guest has no config, so the control plane returns `grant_issuer_pubkey` in the **redeem** response and the guest pins that for the session. Absent ⇒ backstage is **denied**, never self-issued — see below. |
| Turning a guest into a permanent agent | `enroll_once` → server-minted `device_id` → pinned key → service `install` (enroll.rs, service.rs) | **none** — the promote path *calls this*, it does not reimplement it |

### Consent to be viewed is not consent to `ShellAsSystem`

A guest who runs `agent_host attend --code …` and clicks Yes has agreed to a **support session**.
That is not agreement to have their registry rewritten or a SYSTEM shell opened, and the control
plane already encodes which of those a given technician may do: `BackstageCapsFor`
(control-plane/grant.go) withholds the admin tier from anyone without `CapManageMachines`, and
expresses the result as a **signed grant**.

So an attended session must require that grant like any other. Concretely:

* `POST /attended-sessions/redeem` returns `grant_issuer_pubkey` (the public half — the same value
  `GET /grant/pubkey` serves the console). It is optional on the wire.
* The guest pins it for the session (`attend_backstage_auth`, host.rs) and denies every backstage
  request until a `Control::InstallGrant` signed by that issuer verifies.
* If the field is absent, empty, or malformed, backstage is **denied for the session**. Screen
  sharing, input, and clipboard are unaffected — the gate is on the tool panels, not the session.

**Why this is called out rather than assumed.** It was originally wrong in exactly the way the table
above invites: attended passed `grant_issuer: None` into the shared session driver, and `None` meant
"self-issue a grant carrying all 19 capabilities". Measured over a real WebRTC session, an
un-granted `KillProcess` came back `exec_failed` ("target not found") rather than `denied` — i.e.
authorized, with only a bogus pid preventing the kill. A technician needed just `CapStartSession`
to get there. The trust policy is now a named three-state type (`BackstageAuth::SignedBy | Deny |
InsecureSelfIssued`) whose **default is `Deny`**, so a future call site cannot inherit the insecure
mode by writing `None` or `..Default::default()`.

### And consent to be watched is not the ability to be recorded

The attended client **cannot record a session at all**, and unlike the backstage gate above this is
not a policy the control plane can turn on — there is no field for it.
`attend_session_options` (host.rs) sets `recording_dir: None` **explicitly**, with the reason next to
it, rather than letting it fall out of `..Default::default()`.

The reason is structural rather than squeamish. A recording is a local, self-expiring working copy;
what makes that acceptable on someone else's machine is the 72-hour TTL, and the TTL is swept at
exactly two moments — **helper start and session start**. An attended client is a downloaded stub
that self-deletes and never runs again, so on that host neither moment ever comes back. A recording
made through `attend` would sit on a member of the public's disk with a deletion deadline that
nothing will ever read: the failure mode the TTL exists to prevent, reached by the one deployment
where the mechanism is absent.

`the_attended_host_is_given_nowhere_to_record` pins it under the production flags *and* both lab
flags, so "recording is off here" cannot become an accident of a test fixture. When attended
recording is genuinely wanted it needs its own sweeper — not this flag flipped.

Because the technician gate is `RMTTICKETv1` and the agent gate is `RMTAGENTAUTHv1`, **M-ATT
introduces no new signed preimage and no new golden vector.** The one-time code is a *bearer secret*
(hashed at rest like an enrollment token), not a signed token. This is the single most important
design decision: it keeps the cross-language byte-exactness surface at zero.

What is genuinely new is small and lives mostly in the control plane: an `attended_session` record,
an ephemeral flavour of a `machine` row, a public redeem endpoint, and the **consent gate** — the
control plane refuses to mint the technician's ticket until the guest has reported consent. Signaling
already refuses to broker without a valid ticket, so *no consent ⇒ no ticket ⇒ no connection*. The
gate is enforced server-side, never merely drawn in the UI.

### 2.1 State machine (one attended session)

```
  technician: POST /attended-sessions
        │  (code minted, hashed at rest; ephemeral device_id NOT yet assigned)
        ▼
   ┌─────────┐  guest POST /attended-sessions/redeem {code,pubkey}
   │ pending │───────────────────────────────────────────────┐
   └─────────┘  (mint ephemeral machine, pin pubkey,          │
        │        return device_id + attend_token + signaling) ▼
        │                                              ┌──────────────┐
        │ code TTL elapses / never redeemed            │   redeemed   │  guest shows consent prompt
        ▼                                              └──────┬───────┘
   ┌─────────┐                                    consent │        │ decline
   │ expired │                                            ▼        ▼
   └─────────┘                                     ┌───────────┐  ┌──────────┐
                                                   │ consented │  │ declined │ (guest exits)
                                                   └─────┬─────┘  └──────────┘
   technician POST /attended-sessions/{id}/connect       │  (ticket minted ONLY here or in `active`)
        │  requires state ∈ {consented,active}           ▼
        │                                          ┌──────────┐
        └─────────────────────────────────────────│  active  │  guest streaming, indicator shown
                                                   └────┬─────┘
                                    end / guest exit /  │  session TTL / guest heartbeat lost
                                                        ▼
                                                   ┌──────────┐
                                                   │  ended   │  (ephemeral machine reaped)
                                                   └──────────┘
```

Normative consequences — each gets a test:

- **A ticket is mintable only in `consented` or `active`.** `POST /attended-sessions/{id}/connect`
  returns `409 {"error":"awaiting consent"}` in `pending`/`redeemed`, `403` in `declined`,
  `410 {"error":"session ended"}` in `ended`/`expired`. This is the consent gate.
- **The guest registers with signaling only AFTER it has POSTed consent.** It MUST NOT `register_agent`
  in `redeemed`. (It *may* generate its key and hold the socket, but it does not become a registry
  entry until consent is recorded — so a technician cannot be brokered to an unconsented guest even
  if they somehow obtained a ticket, because the broker's registry lookup would miss.)
- **`declined` and `expired` are terminal.** The guest exits on decline; the code cannot be re-redeemed.
- The ephemeral `machine` row is **not** listed by `GET /machines` and is reaped at `expires_at`.

---

## 3. The one-time code and the attend token

Two bearer secrets, both generated with `crypto/rand`, both **hashed at rest** (SHA-256, like
`enrollment_token` and login sessions — `HashToken`/`hashKey`), both never returned after their
single issuance:

| Secret | Who holds it | Entropy | TTL | Uses | Purpose |
|---|---|---|---|---|---|
| **attend code** | the user (typed / in the join link) | 40 bits (new codes) | `AttendedCodeTTL` = 10 min (default) | 1 | redeem → ephemeral identity |
| **attend token** | the guest process (returned by redeem) | 256 bits | until session `ended` | n | authorize guest → CP calls (consent/decline/status/heartbeat) |

**Attend code format.** Crockford base32 (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, no
`I L O U`), 8 chars (40 bits; legacy 13-character codes remain valid), displayed grouped `XXXX-XXXX` and echoed into the join link
`…/join#<code>` (fragment, so it never hits an access log or the CP as a query param). Redemption is
case-insensitive and strips `-`/whitespace. Guessing is bounded by the 10-min TTL, single use, and
per-source throttle on `/attended-sessions/redeem` (reuse `throttle.go`, key `ipKey("attend-redeem",
clientIP)`), exactly as `/enroll/redeem`.

**Attend token** is a `base64url` 32-byte secret. Presented as `Authorization: Bearer <attend
token>` on the guest→CP calls; compared constant-time against the stored hash.

---

## 4. Data model (owner C) — migration `0013_attended_sessions.sql`

`0013` is the next free number (0001–0012 exist). Two changes:

### 4.1 `machine` gains an ephemeral flavour

```sql
ALTER TABLE machine ADD COLUMN ephemeral   boolean     NOT NULL DEFAULT false;
ALTER TABLE machine ADD COLUMN expires_at  timestamptz NULL;
-- Reap index for the sweeper and the identity-lookup expiry check.
CREATE INDEX machine_ephemeral_expiry_idx ON machine (expires_at) WHERE ephemeral;
```

- A permanent (unattended) machine has `ephemeral=false, expires_at=NULL` — existing rows are
  unaffected by the defaults.
- An attended guest is `ephemeral=true, expires_at = now() + AttendedSessionTTL` (30 min default).
- RLS: no new policy — `machine` already has tenant RLS; ephemeral rows inherit it.

### 4.2 `attended_session`

```sql
CREATE TABLE attended_session (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES tenant(id),
    group_id     uuid NOT NULL,                 -- the group the technician acts in; scopes promote/backstage
    technician_id uuid NOT NULL,
    code_hash    bytea NOT NULL,                -- SHA-256 of the attend code; UNIQUE so redeem is a point lookup
    token_hash   bytea NULL,                    -- SHA-256 of the attend token; set at redeem
    device_id    text  NULL REFERENCES machine(device_id), -- the ephemeral machine, set at redeem
    state        text  NOT NULL DEFAULT 'pending'
                 CHECK (state IN ('pending','redeemed','consented','declined','active','ended','expired')),
    reason       text  NOT NULL DEFAULT '',     -- shown to the user in the consent prompt
    consent_user text  NOT NULL DEFAULT '',     -- who consented (OS username the guest reports)
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,          -- code redemption deadline (created_at + AttendedCodeTTL)
    redeemed_at  timestamptz NULL,
    consented_at timestamptz NULL,
    ended_at     timestamptz NULL
);
CREATE UNIQUE INDEX attended_session_code_hash_idx ON attended_session (code_hash);
CREATE INDEX attended_session_tenant_idx ON attended_session (tenant_id, created_at DESC);

ALTER TABLE attended_session ENABLE ROW LEVEL SECURITY;
CREATE POLICY attended_session_tenant_isolation ON attended_session
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
GRANT SELECT, INSERT, UPDATE ON attended_session TO rmt_app;
```

### 4.3 SECURITY DEFINER redeem (pre-tenant, like enrollment)

Redemption is unauthenticated (the code is the authorization) and cross-tenant-blind, so it runs
through a SECURITY DEFINER function, mirroring `cp_enrollment_token_redeem` (0007) and following
0007's posture exactly (pinned `search_path`, `GRANT EXECUTE … TO PUBLIC`, header comment on why the
RLS bypass is necessary and safe):

```sql
CREATE FUNCTION cp_attended_redeem(p_code_hash bytea, p_pubkey bytea, p_name text,
                                   p_device_id text, p_token_hash bytea, p_machine_expires timestamptz)
    RETURNS TABLE (session_id uuid, tenant_id uuid, group_id uuid, device_id text)
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_catalog
AS $$
DECLARE s attended_session%ROWTYPE;
BEGIN
    SELECT * INTO s FROM attended_session
        WHERE code_hash = p_code_hash AND state = 'pending' AND now() < expires_at
        FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;                 -- caller maps empty → ErrAttendedInvalid
    INSERT INTO machine (tenant_id, device_id, group_id, hostname, pubkey, ephemeral, expires_at)
        VALUES (s.tenant_id, p_device_id, s.group_id, p_name, p_pubkey, true, p_machine_expires);
    UPDATE attended_session
        SET state='redeemed', device_id=p_device_id, token_hash=p_token_hash, redeemed_at=now()
        WHERE id = s.id;
    RETURN QUERY SELECT s.id, s.tenant_id, s.group_id, p_device_id;
END $$;
GRANT EXECUTE ON FUNCTION cp_attended_redeem(bytea,bytea,text,text,bytea,timestamptz) TO PUBLIC;
```

Test-harness obligations (mandatory for any new `cp_*` function): add the `DROP FUNCTION IF EXISTS
cp_attended_redeem(...)` to `resetSchema`'s DROP list in `pgstore_test.go`, and an
`applyAttendedMigration(t, pool)` helper following `applyEnrollmentMigration`.

### 4.4 Identity-lookup expiry (owner C)

`LookupDeviceIdentity` (machine.go / pgstore.go) MUST refuse an ephemeral machine past its
`expires_at` — return `ErrMachineNotFound` — so signaling will not authenticate a guest whose
attended session has expired. Non-ephemeral machines are unaffected. Assert this with a test.

---

## 5. Control-plane API (owner C)

All authenticated routes sit behind the existing auth → tenant (RLS) chain and record management
audit (`recordMgmtAudit`) exactly like sessions/enrollment.

**The two PUBLIC routes are audited too, with an EMPTY actor** — `attended.redeem` and
`attended.consent`, recorded via `MgmtAudit.RecordEvent` directly because `recordMgmtAudit` reads the
actor and tenant from a request principal the guest does not have. This is the same idiom
`POST /enroll/redeem` uses for `machine.enroll`, and it was added after both were found
missing: the redemption plants an ephemeral machine into the tenant with no record, and the CONSENT
DECISION — the load-bearing rule of this whole document, the single fact that authorizes a
technician to see the desktop — left no audit event at all. **Both decisions are recorded**
(`decision: accept|decline`, plus `consent_user` and the source IP); a trail carrying only
acceptances would read as complete while being incomplete in exactly the direction a disputing
guest cares about. The actor stays empty deliberately: attributing the guest's action to the
technician who opened the session would put a false claim in the trail. **NOT SHIPPED AS DESIGNED:** this
paragraph planned a new capability `CapStartAttendedSession`; the implementation deliberately reuses
`CapStartSession` instead, because attended is "starting a session on demand" and a new capability would
have needed a role-seed migration (see the header of `control-plane/http_attended.go`). Read every
`CapStartAttendedSession` on this page as `CapStartSession`; `promote` additionally requires
`CapEnrollMachine` in the session's group. Group scoping mirrors `handleStartSession`
(`RequireMachine`-style checks against `attended_session.group_id`).

**Every `{id}` route resolves the session first and gates on the group the STORE reports** — the
tenant is not the boundary. This paragraph described the intent from the start, but `GET
/attended-sessions/{id}` alone was implemented with the tenant-wide `Require(CapViewSessions)`, so a
technician scoped to one group could read the whole record — group, technician, ephemeral device,
state and the free-text `reason` — of a session in a group they held no rights over. Closed in loop
10; `TestGetAttendedIsScopedToTheSessionsGroup` pins it, together with the negative control that a
caller can still read its own group's sessions.

| Route | Auth | Body / result | Notes |
|---|---|---|---|
| `POST /attended-sessions` | technician, `CapStartSession` in `group_id` | `{group_id, reason?}` → `201 {session:{id,state,expires_at}, code, join_url}` | mints the code (shown ONCE); `code`/`token` never returned again |
| `GET /attended-sessions/{id}` | technician, `CapViewSessions` **in group** | `200 {session}` | technician polls state + `device_id`; resolves the session then gates on its stored `group_id`, exactly like `GET /machines/{id}` |
| `POST /attended-sessions/{id}/connect` | technician, `CapStartSession` in group | `200 {session, signaling:{url,device_id,session_id,ticket}, session_policy?:{access,signed}}` | **consent gate**: only in `consented`/`active`; mints `RMTTICKETv1` for the ephemeral device (reuses `MintSessionTicket`), transitions → `active`. Also mints the SIGNED SESSION POLICY — see § below |
| `POST /attended-sessions/{id}/promote` | technician, `CapEnrollMachine` in group | `200 {}` | mints a normal enrollment token for the group, records it against the session so the guest picks it up on its next status poll |
| `POST /attended-sessions/{id}/end` | technician, `CapEndSession` **in group** | `200 {session}` | → `ended`; reaps the ephemeral machine |
| `POST /attended-sessions/redeem` | **PUBLIC** (code is authz), throttled | `{code,pubkey,name}` → `201 {device_id,tenant_id,signaling_url,attend_token, grant_issuer_pubkey?, require_session_policy?}` | mints ephemeral machine (device_id server-minted), pins pubkey, → `redeemed`. Audited `attended.redeem` (empty actor; `device_id`/`group_id`/`ip`) |
| `POST /attended-sessions/consent` | guest, `Bearer <attend_token>` | `{decision:"accept"|"decline", consent_user}` → `200 {}` | accept → `consented`; decline → `declined`. Audited `attended.consent` (empty actor; `decision`/`consent_user`/`ip`) — **both** decisions |
| `GET  /attended-sessions/status` | guest, `Bearer <attend_token>` | `200 {state, promote?:{enrollment_token,control_plane_url}}` | guest polls for `end`/`promote` |

Mounting mirrors enrollment: the public `redeem` and the two guest `Bearer`-authed routes go on the
**root** mux (they are not tenant principals), only when the attended store is wired; the technician
routes go on the protected mux.

### The signed session policy, and the two fields redeem adds (loops 81–83)

Three fields above did not exist when this table was first written, and they carry the whole per-group
view-only mandate on this path. They are documented here because this is the file a reader consults to
answer "what does redeem tell the guest, and what does connect decide".

**`redeem` → `grant_issuer_pubkey`**. The guest's trust anchor. An attended guest has no
config file, so this response is the only channel that can tell it which issuer to trust; without it the
guest can verify no signed material at all. Publishing the PUBLIC half is safe — it authorizes nothing
and can only make the guest stricter. Omitted when no issuer is configured, which the guest reads as
"deny backstage".

**`redeem` → `require_session_policy`**. "Open this session VIEW-ONLY until a signed policy
verifies." Sent when the invite's group has `enforce_view_only`. It exists because a signed policy
reaches the agent only because the VIEWER forwards it, and the viewer is exactly the party the policy
restricts — so without this a patched console could simply withhold the frame and keep full control.
**COUPLED to `grant_issuer_pubkey`: both ship or neither**, since a guest that pinned no issuer could
never verify the policy that lifts the floor, and would be stranded view-only for the session's life.
An unresolvable group policy FAILS the redeem rather than opening the session unfloored.

**`connect` → `session_policy`** (loops 81/83). `{access: "view_only"|"control", signed: "<JSON>"}`. The
viewer forwards `signed` verbatim to the agent over `Control::InstallSessionPolicy`; the agent verifies
it against the pinned issuer and enforces it as a one-way ratchet. Minted when **either** the group
enforces view-only **or** the session carries `require_session_policy` (migration 0036), and the level is
the group's CURRENT one:

| group enforces | guest was told to floor | minted | `access` |
|---|---|---|---|
| no | no | no policy | — |
| yes | no | yes | `view_only` |
| yes | yes | yes | `view_only` |
| **no** | **yes** | **yes** | **`control`** |

That last row is a later fix. The floor instruction is sampled at redeem and the mint decided at
connect, so clearing the mandate in between used to leave the guest floored with nothing ever arriving to
release it. A `control` policy is precisely what the agent's ratchet accepts to discharge a PROVISIONAL
floor — and only a provisional one, so this cannot relax a floor that arrived as a verified policy.

**SCOPE, stated plainly:** the mandate covers what `AccessLevel::ViewOnly` covers — injected input and
the write-actions (reboot / tool-launch / command-run / lock / log-off / shut-down). It does NOT cover
BACKSTAGE, which is a separate trust axis gated by a signed grant. See the note on `EnforceViewOnly` in
`control-plane/group_session_policy.go`. Every invalid code / bad attend token is the **same generic**
`403`/`401` as the enrollment paths — a prober learns nothing.

`POST /attended-sessions/redeem`, like `/enroll/redeem`, mints the `device_id` **server-side** and
ignores any client-supplied id (a redeemer choosing the device id would be choosing which agent a
ticket authorizes). `pubkey` is REQUIRED (hex 32-byte Ed25519); the ephemeral machine's
`expires_at` is `now + AttendedSessionTTL`.

Persistence follows the repo's interface-plus-fakes pattern: `AttendedStore` interface +
`InMemoryAttendedStore` (dev/tests) + `PgAttendedStore` (pgstore_attended.go). The in-memory store's
redeem is under a mutex (single-use holds under concurrency exactly as the single-UPDATE pg path).

---

## 6. Signaling (owner S) — NO protocol change

Signaling needs **no changes**: the guest is a normal agent whose ephemeral key is resolvable via
`GET /internal/devices/{id}/identity`, and the technician presents a normal `RMTTICKETv1`. The only
S-side work is a test: `attended_e2e_test.go` (or an addition to an existing e2e) that drives the
full path against an enforcing signaling to prove an *unconsented* guest cannot be brokered (its
registry entry does not exist until consent) and a *consented* one can. If review finds any place
where signaling special-cases ephemeral devices, that is a bug — remove it.

---

## 7. Agent (owner R) — the `attend` guest client

New subcommand on the `agent_host` binary:

```
agent_host attend --code <CODE> --control-plane-url <URL> [--reason <text>] [--auto-consent]
```

New module `crates/agent-windows/src/attend.rs`. Flow:

1. Generate an **ephemeral** `Identity::generate()` — held in memory, **never written to disk**
   (contrast enroll.rs, which persists). No `config.json` is written or read.
2. `POST <URL>/attended-sessions/redeem {code, pubkey, name}` (blocking reqwest, rustls, cert
   validation ON, same URL policy as enroll.rs: https except loopback). On `201` read
   `{device_id, tenant_id, signaling_url, attend_token}`.
3. **Consent.** Show a native prompt (`MessageBoxW`, `MB_YESNO | MB_ICONQUESTION | MB_SYSTEMMODAL`,
   topmost): *"<reason or 'A support technician'> is requesting to view and control this computer.
   Allow?"*. `--auto-consent` (or env `RMT_ATTEND_AUTO_CONSENT=1`) accepts without prompting — this
   is TEST-ONLY and MUST log a loud warning, exactly like the signaling `-insecure-*` flags. On
   accept → `POST /attended-sessions/consent {decision:"accept", consent_user:%USERNAME%}`; on
   decline → `POST …/consent {decision:"decline"}` then exit 0.
4. **Register + stream** using the ephemeral identity: reuse `host::serve_session` /
   `stream_screen` with `device_id`, `tenant_id`, and an `IdentitySigner` over the ephemeral key —
   the *same* code path unattended uses. The guest answers the `agent_auth_challenge` with
   `RMTAGENTAUTHv1` (its pubkey is pinned). No behavioural difference from unattended streaming.
5. **On-screen indicator.** For the whole streaming lifetime show a small always-on-top borderless
   window (or, minimally, keep the consent affordance's tray presence) reading *"Remote support
   session in progress"* with an End button. Closing it / clicking End tears down the session
   (`POST …/end` best-effort) and exits. The indicator is a **product requirement**, not optional;
   `--auto-consent` mode MAY render it off-screen but MUST still create it (so a test can assert it
   exists). Reuse the secure-desktop/topmost-window plumbing from the spike where practical.
6. **Poll `GET /attended-sessions/status`** every few seconds. On `state==ended` → tear down + exit.
   On a `promote` payload → **promote** (§8).
7. **No persistence to clean up.** The binary MAY best-effort self-delete its own on-disk copy on
   exit (it was downloaded per-session), but nothing else is left behind — there is no identity key
   and no config.

Blocking-I/O rule from enroll.rs applies: the redeem/consent/status calls use the blocking client
and must not run inside the tokio runtime; do them before/around the streaming runtime as enroll does.

### 7.1 Consent is also enforced server-side

The guest showing a prompt is necessary but not sufficient: the control plane will not mint a ticket
until it has recorded consent (§5 connect gate). So even a patched guest that skips the prompt cannot
grant a technician access without the CP transitioning to `consented` — and the *honest* transition
is the guest's `POST …/consent`. A malicious guest binary is out of scope (it runs on the user's own
machine at the user's invitation); the gate defends the **technician/relay** side and the audit trail.

---

## 8. Promote to unattended (owner R + C) — reuse enrollment verbatim

The promote path MUST NOT introduce a second identity mechanism. It is:

1. Technician clicks "Install unattended" → `POST /attended-sessions/{id}/promote` → CP mints a
   normal enrollment token (`MintToken`, group = the session's `group_id`, single-use, short TTL)
   and stashes it on the attended session for pickup. Audited `attended.promote`.
2. Guest's next `GET /attended-sessions/status` returns `promote:{enrollment_token,
   control_plane_url}`.
3. Guest runs the **existing** `enroll_once(cfg{control_plane_url, enrollment_token}, C:\rmt-agent\
   config.json)` (enroll.rs) — redeem token → server-minted **permanent** `device_id` → write
   `identity.key` (ACL-tightened) → clear the token — then the **existing** service `install`
   (service.rs / the `install` subcommand): copy the binary to `C:\rmt-agent`, register the
   LocalSystem service, start it.
4. The now-permanent service registers with its persisted key; the ephemeral attended machine is
   reaped at its `expires_at` (or the session `end`). The two identities never share a code path —
   promote *invokes* enrollment, it does not duplicate it.

Elevation: `install` needs admin. If `attend` is not elevated, promote MUST re-launch the install
step elevated (UAC) — the user is present and consenting, so a UAC prompt is acceptable and expected.

---

## 9. Web viewer (owner W)

- **Console → "Start attended session"**: `POST /attended-sessions {group_id, reason}` → show the
  **code** (grouped, copyable) and the **join link**; poll `GET /attended-sessions/{id}`. When
  `state==consented`, enable **Connect** → `POST …/connect` → feed the returned `signaling` into the
  existing transport (the same path the machine list's Connect uses). Show consent/decline/expiry
  status. A **Promote to unattended** button → `POST …/promote`.
- **Guest landing page** `GET /join` (fragment carries the code): a minimal page that detects the OS
  and offers the one-time client download, with the code pre-filled, plus copy-paste run
  instructions. In dev/e2e the download is skipped and the `attend` binary is run directly.
- `console_api.ts` gains the attended calls; keep the typed-response discipline of the existing
  client. No change to the transport layer.

---

## 10. Work split

Ownership is exclusive. If a file is not on your list, do not edit it — including tests.

### 10.1 C — control-plane (`control-plane/**`)
- `attended.go` (new): `AttendedSession`, `AttendedStore` interface, `InMemoryAttendedStore`, code/
  token mint+hash. (No new capability: the routes reuse `CapStartSession` — see §9.)
- `pgstore_attended.go` (new): `PgAttendedStore` incl. `cp_attended_redeem` call, ephemeral machine
  reap query.
- `migrations/0013_attended_sessions.sql` (new).
- `http.go`: the seven routes (§5), mounting, consent gate, audit.
- `machine.go` / `pgstore.go`: `ephemeral`+`expires_at` on `Machine`, `LookupDeviceIdentity` expiry
  refusal, `ListMachines` excludes ephemeral.
- `pgstore_test.go`: `resetSchema` DROP + `applyAttendedMigration`; `attended_test.go`,
  `attended_pgstore_test.go`, `http_test.go` coverage (redeem, consent gate, promote, expiry,
  throttle, generic errors, ephemeral hidden from listing).

### 10.2 S — signaling (`server/signaling/**`)
- No protocol change. Add an attended path assertion to the e2e (unconsented guest not brokerable;
  consented guest is). Only edit signaling tests + (if needed) a comment noting ephemeral devices are
  ordinary agents.

### 10.3 R — Rust agent (`crates/agent-windows/**`, `agent`)
- `src/attend.rs` (new): redeem, consent (`MessageBoxW`/`--auto-consent`), stream via `serve_session`,
  indicator window, status poll, promote-via-`enroll_once`+`install`.
- `src/bin/agent_host.rs`: the `attend` subcommand + arg parsing.
- `Cargo.toml`: reuse existing deps (`reqwest`, `windows`); no new golden-vector deps.
- Tests: `attend.rs` unit tests (redeem-response parse, consent decision→CP body, promote payload
  parse) mirroring enroll.rs's test style; an e2e is W's `attended.spec.ts` (below) driving the real
  binary with `--auto-consent`.

### 10.4 W — web viewer (`web/viewer/**`)
- `src/lib/console_api.ts`: attended calls.
- Console UI: start/poll/connect/promote panel; `join` landing page.
- `e2e/attended.spec.ts` (new): the live proof (§11). Reuse `e2e/ports.ts` + the CP/signaling/agent
  orchestration pattern of `secure_grant.spec.ts`; run the guest as `agent_host attend
  --auto-consent`. Follows the no-skip rule (a missing binary/browser skips loudly; a real failure
  fails).

### 10.5 Contested / frozen
| File | Owner | Note |
|---|---|---|
| `docs/12-attended-sessions-contract.md` | nobody | frozen during the implementation pass |
| `crates/protocol/**` golden vectors | nobody | M-ATT adds **no** new preimage |
| `scripts/verify-all.ps1` | integration | add the attended e2e once it exists; it is picked up automatically by the Playwright suite |
| `dist/**`, `scripts/build-release.ps1` | nobody | packaging the one-time client is a follow-up |

---

## 11. Definition of done — prove it live

- Migrations 0001–0013 apply; `go test ./...` green in control-plane with `TEST_DATABASE_URL` set
  (the attended pg tests RUN, not skip — verify wall time).
- Consent gate proven: `POST …/connect` returns 409 before consent and a valid ticket after; a test
  asserts a ticket is *not* obtainable in `pending`/`redeemed`.
- **Live end-to-end** (the acceptance test, `attended.spec.ts`, run by the no-skip harness):
  1. technician `POST /attended-sessions` → code;
  2. `agent_host attend --code … --auto-consent` redeems, consents, registers, streams;
  3. technician `POST …/connect` (only succeeds post-consent) → browser connects over the *existing*
     WebRTC path and receives inbound RTP video from the guest;
  4. `POST …/promote` → the guest runs `enroll_once` + service `install` and comes back as a
     permanent machine with a persisted key (assert the machine is now non-ephemeral and the identity
     key exists) — reusing the enrollment path, not a second one.
- `go vet ./...` clean; `cargo test` green with `RUSTFLAGS="-C debuginfo=0" CARGO_INCREMENTAL=0`;
  all Playwright specs pass. No new skips in the harness.

## 12. Rejected alternatives

- **A distinct "attended identity" protocol / a second signed token.** Rejected: it would add a
  cross-language canonical preimage + golden vector — the exact drift surface docs/11 paid down. The
  ephemeral-machine approach reuses `RMTAGENTAUTHv1`/`RMTTICKETv1` unchanged.
- **A separate ephemeral store that signaling's identity lookup also consults.** Rejected: it forks
  the one code path (`LookupDeviceIdentity`) signaling depends on. One `machine` table with an
  `ephemeral` flag keeps signaling oblivious.
- **Consent enforced only in the guest UI.** Rejected: a patched guest or a replayed ticket would
  bypass it. The control-plane connect gate makes consent load-bearing on the authorization path.
- **Persisting the guest's ephemeral key (like enroll).** Rejected: an attended guest is by
  definition throwaway; persisting a key it will never reuse only creates cleanup and a stray
  credential. Promote generates a *fresh permanent* key through `enroll_once`.

---

## 13. The downloadable guest stub (§9's "one-time client")

§9's guest landing page offers a **download** for a machine that has never run the client — the
entry point the `rmt://` URI scheme *cannot* be (a machine with no handler registered gets a silent
no-op, docs/01 §12). The download is the productized `agent_host.exe` with the session's parameters
**patched into a placeholder inside the binary**. It is measured from a real
`ScreenConnect.ClientSetup.exe` (memory `screenconnect-stub-mechanism`), not invented.

### 13.1 Mechanism (`crates/agent-windows/src/stub.rs`)

* **The placeholder** is `RMT_STUB_SLOT`, a `#[used] #[no_mangle] static [u8; SLOT_LEN]` =
  `[32-byte magic][u32 little-endian length][payload…]`. A pristine (shipped) binary has length 0.
* **What is embedded is exactly a `crate::uri` attend link** — `rmt-<fp>://attend?code=…&cp=…[&reason=…]`,
  the identical string the console's `attendLaunchUri` builds for the URI-scheme path. So the stub
  reuses `parse_attend_uri` **verbatim** and runs the attended flow through the same
  `attend_params_from_uri` → `run_attend` path a clicked link takes, with `auto_consent = false`. A
  configured stub is therefore identical in security posture to a clicked link; it just needs no
  handler registered first.
* **Run with no subcommand** (a double-click), `agent_host` reads its OWN executable file, scans for
  the single magic, recovers the URI, and self-configures. A normally-built `agent_host` has length 0
  and prints usage instead — only a patched copy becomes a guest.
* **Surviving compilation is the fiddly part, and it was measured** (a spike, then the release
  binary): the magic is stored in source only XOR-obfuscated, and the runtime search needle is fed
  through `std::hint::black_box` so the optimizer cannot const-fold a *second* plaintext magic into
  `.rdata`. A non-zero filler keeps the static in `.rdata` (not `.bss`), and `#[used]`+`#[no_mangle]`
  keep it through the rlib→bin link. The invariant — **exactly one pristine slot in the shipped
  release binary** — is enforced under the gate by `build-release.ps1`'s `Assert-StubSlot` (the unit
  test only sees the unoptimized test binary, where the const-fold/LTO risks cannot appear).

### 13.2 The patcher — `agent_host make-stub`

```
agent_host make-stub --uri "rmt-<fp>://attend?code=<CODE>&cp=<https-url>[&reason=<text>]" \
                     --out guest.exe [--template <exe>]
# or, to keep the one-time code off the command line:
agent_host make-stub --uri-file uri.txt --out guest.exe
```

The template defaults to the running `agent_host.exe` (the shipped binary **is** the template), so a
server generates a download by calling `make-stub` on itself. `make-stub` validates the URI with the
same `parse_attend_uri` the stub will use (one validation path), then writes the payload into a copy.
**The output is UNSIGNED** — patching the slot invalidates any Authenticode signature — so the caller
MUST re-sign it. `scripts/sign-release.ps1` already timestamps (a re-signed per-download binary keeps
its publisher's SmartScreen reputation because reputation is publisher-based, not per-file-hash).

### 13.3 Server-side integration (the deployment seam)

> **SUPERSEDED for first contact by the typed-code design (docs/27, docs/28).** The per-download
> build → patch → re-sign → serve chain described below is **NOT REQUIRED** for the downloadable
> support client. That client is ONE static artifact (`DeskRallySupport.exe`) with the control-plane
> origin baked at build time; the customer types the session code, so there is no per-download config
> patching, no server-side re-signing per session, and no signing key in a serving container. The
> `make-stub` mechanism (§13.2) still exists for the pre-configured `rmt://`-link guest stub, but the
> first-contact path no longer depends on it. See `docs/27-first-contact-download.md`.

A control plane serving a per-download STUB would, per attended session: build the attend URI (the
console's `deploymentScheme`/`attendLaunchUri` logic), call `agent_host make-stub`, re-sign with the
operator's cert, and serve the bytes. That chain needs the operator's code-signing key and a template
binary present at deploy time; it is an **ops integration**, not tested in this repo, and — per the
banner above — not the way the first-contact download works. `make-stub` is the piece it calls, and
that piece is fully built and proven.

### 13.4 What is proven, and what CANNOT be proven here

* **Proven (local + release):** the pristine binary carries exactly one empty slot; `make-stub`
  embeds the URI; a configured copy run with no arguments self-configures and dials the *embedded*
  control plane; an unconfigured binary prints usage; the patched PE still loads. Unit tests cover
  locate/patch/read (each mutation-lethal); `Assert-StubSlot` gates the release artifact.
* **Unprovable in this environment, shipped and SAID so:** **Mark-of-the-Web / SmartScreen.** No
  `Copy-VMFile`/SMB transfer carries MOTW, so nothing here says anything about download reputation or
  the SmartScreen prompt a browser-downloaded stub faces. The server-side per-download *serving +
  signing* chain (§13.3) is likewise a deployment integration, not exercised here.

### 13.5 Divergence from ScreenConnect: no embedded server key (`k`)

ScreenConnect embeds the server's public key for first-contact pinning. RMT does **not**: the redeem
is HTTPS with certificate validation on (rustls native roots), and the grant-issuer key the guest
pins for backstage rides in the redeem response (§2). The embedded `cp` URL's TLS certificate is the
first-contact trust anchor. The one honest consequence: a *private-CA* RMT deployment needs the
guest's machine to trust the operator's CA for the redeem — the same requirement the attended flow
already had. Pinning an embedded key is a recorded future option, not shipped.

### 13.6 The window `[X]` footgun — CLOSED

Previously the guest window's `[X]` (and Alt+F4 / the system menu's Close) only **hid** the indicator
while the session kept streaming — the "RAT with no indicator" posture §1 calls a legal problem, and,
worse, one an attacker could actuate: the technician's injected mouse could click the `[X]` to make
the "session ACTIVE" indicator vanish while control continued.

The client now makes `[X]`/Alt+F4/Close behave exactly like the on-screen **End session** button, which is
what §5 has always specified ("Closing it / clicking End tears down the session"). `WM_CLOSE` now
routes through `guest_window::UiState::on_user_close`: while the session is **Active** it dispatches
`GuestEvent::EndClicked` → `GuestToHost::End` (the host tears the session down; the window is left up
for the session's own teardown to close, keeping one authority for "the session is over"); once
**Ended** it destroys the now-dismissable receipt window. The host's own teardown was moved to a
private `WM_RMT_DESTROY` message so it cannot be confused with a user close (a `WM_CLOSE` that carried
End semantics would otherwise deadlock `GuestWindow::close`'s thread join, or send a spurious `End`
into an already-ending session). The pure decision (`close_action`) and the full wiring
(`on_user_close`, driven through a real `to_host` channel) are both unit- and mutation-tested; the
Win32 `WM_CLOSE`→dispatch path is VM-verified (the stream stops when `[X]` is clicked, not merely the
window vanishing — which the old bug also did).

**Injected mouse is now dropped too.** The pump's tag filter previously covered only
injected KEYBOARD, so a technician's injected click could reach the `[X]`/End button (benign — its only
effect was to end a session the remote already controls, and it could not suppress the indicator). Loop
22 extended the same `GetMessageExtraInfo() == RMT_INJECTED_TAG` drop to the mouse ACTUATOR messages —
`WM_LBUTTONDOWN`/`WM_LBUTTONDBLCLK` (the End button) and `WM_NCLBUTTONDOWN`/`WM_NCLBUTTONDBLCLK` (the
caption `[X]`, which DefWindowProc turns into `SC_CLOSE` → `WM_CLOSE`), via `is_mouse_actuator_message`.
Dropping the button-down before `DispatchMessageW` means the End is never dispatched and the close is
never synthesized. The **system-menu route is closed at its entrance too**: an injected caption
right-click (`WM_NCRBUTTONDOWN`/`WM_NCRBUTTONUP`) would otherwise make DefWindowProc pop the window
menu, whose *Close* runs in a modal `GetMessage` loop this pump never services (so the tag check could
not catch the click that selects *Close*) — so the injected right-click is dropped before the menu can
open (a genuine untagged guest right-click still opens it). The guest's own **genuine hardware** clicks
carry `dwExtraInfo == 0` and are untouched; only this agent's own (tagged) injections are dropped.
Non-actuators — pointer moves, left button-ups, client-area right/middle buttons — are deliberately NOT
filtered (dropping the injected move would break the technician steering the cursor toward legitimate
targets). So the guest's safety affordances now accept only genuine input, symmetric with the keyboard
filter, with no remaining injected mouse route to End/close.

Predicate coverage is unit- + mutation-tested (dropping `WM_NCLBUTTONDOWN` and over-broadly adding
`WM_MOUSEMOVE` are both lethal); the actual pump drop is VM-verified with `RMT_LOG=debug`: injected
clicks on the `[X]` and the End button were logged *dropped* (`message 161` = `WM_NCLBUTTONDOWN`,
`message 513` = `WM_LBUTTONDOWN` — the NC message carrying the tag being the load-bearing assumption)
while the session kept streaming and logged **no** `guest ended…` — the inverse of the positive
proof for `[X]`/Close above. Proving a *genuine* (untagged) click still closes the `[X]` needs a physical click and is a
human-only check (the agent's own `SendInput` always stamps the tag). A right-click could still reach
the menu only via a two-injection *keyboard-then-mouse* dance already blocked at the keyboard step.


### Shared console session discovery

The Support session panel lists persisted attended sessions across browser/device logins and across technicians in the same tenant. GET `/attended-sessions?limit=50&offset=0` requires `CapViewSessions`; tenant and capability-specific machine-group scope are applied before pagination. Results are ordered by creation time and ID, newest first, and return `{sessions, has_more}`. The maximum page size is 100. Existing connect, promote and end permission checks still apply to the selected record.

Selecting a record restores its status and controls without an invitation code. Codes remain one-time display values, hashed at rest; they cannot be recovered by listing or reading a session. An unredeemed invitation with a lost code needs a new invitation. The list is session history, not proof that the guest is online. The current Support executable serves one connection per run; if that connection has ended, start a new support session with the guest. This console change does not introduce unattended reconnection or extend guest consent.


### Short join codes (October 2026)

New invitations use eight random Crockford characters (40 bits), displayed as `XXXX-XXXX`, replacing the original 13-character/64-bit format described above. Existing 13-character codes remain accepted by redemption, links and support bundles. The installed Support client already accepts both formats through its existing safe-character validator; no client update is required. Codes retain the ten-minute redemption deadline, single-use redemption, hashed storage and failed-attempt throttling. They are join codes, not cryptographic signing keys; agent identity and grant signatures are unchanged. The unique code-hash index prevents reuse, including across tenants and historical sessions.

### Guest End on an UNATTENDED machine (October 2026)

The guest window's **End** button also appears during unattended sessions. There it is a consent and
courtesy signal, **not** an access revocation. Unattended access is authorized by tenant RBAC and machine
policy: a technician may deliberately reconnect afterwards, and that reconnect is a new, audited session.
Revoking a technician's access is the console's End session, group policy and RBAC.

What a guest End guarantees: the technician's viewer does **not reconnect automatically**. Two paths
carry the end:

1. **Viewer message (fast feedback).** The agent sends `ControlMessage::SessionEndedByGuest` on the
   control channel before teardown. The viewer refuses its automatic recovery and shows "The guest ended
   the session". This needs a viewer that includes this change and an agent that sends it.
2. **Authoritative end.**
   - The agent reports `guest_ended_session {control_plane_session}` on its AUTHENTICATED signaling
     connection.
   - Signaling forwards it to the control plane: `POST /internal/sessions/{id}/guest-ended`, service
     token, carrying the device and tenant that signaling authenticated.
   - The control plane, in ONE transaction: locks the device's machine row, ends the session record only
     if that machine owns it, and appends the `session.end` audit event. The event has no human actor;
     its metadata is `actor_kind=device`, `reason=guest_ended`, `via=signaling`.
   - Recovery's first step renews the original record. It now receives `409 session has ended` and
     refuses, even without the viewer message.
   - The agent keeps the report until signaling answers `ended`, `already_ended` or `refused`. It retries
     `unavailable` (2 s doubling to 60 s) and re-sends after every re-registration.

**Exceptions: an automatic reconnect can still happen when ALL paths that would stop it fail.**
- The agent helper restarts before the report is acknowledged (the pending set is in memory) AND the
  viewer message was lost.
- The report is delayed past recovery's authorization check (at least 2 s after the transport drops),
  for example by a control-plane or signaling outage, AND the viewer message was lost.
- 64 unacknowledged reports are already pending: a new one is logged (`guest_end_unqueued`) and not
  queued.
- Signaling predates the report: it answers "unsupported message type", and the agent keeps the report
  at the 60 s backoff and never drops it.
- `refused` is terminal. The device no longer owns the record or is no longer in the tenant, and no
  retry can change that.
- Old components: agents older than 1.3.2 send neither message; viewers older than this change ignore the
  viewer message; control planes and signaling servers older than this change have no route. In each
  case the other path, if present, still applies.
- Dev mode: signaling running with `-insecure-no-agent-auth` refuses reports, because an asserted
  device id must not end records.
