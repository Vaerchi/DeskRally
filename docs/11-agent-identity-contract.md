# Agent Identity Contract (M3) — authenticated `register_agent`

Implementation contract for three independent implementers: **R** (Rust), **S** (Go signaling),
**C** (Go control-plane). It is normative. Where it says MUST, deviating is a bug, not a style
choice. Read [§8 Work split](#8-work-split) before touching a file.

Status: shipped. Authenticated `register_agent` is implemented in the agent, signaling server and
control plane. This document is the contract it was built to; §1 describes the original gap.

---

## 1. The hole

Originally, `server/signaling/main.go` `dispatch` → `case *RegisterAgent:` had no authentication (a
`TODO(auth)` said so; it has since been removed). The connection asserts its device id, tenant and pubkey, and
`Registry.Register` **closes the incumbent socket** for that device id (registry.go, "last
registration wins"). A device id is an identifier, not a secret. So anyone who learns one can:

1. open `/ws`, send `register_agent{device: <victim>}`,
2. cause the real agent's socket to be closed,
3. receive the next technician's `brokered` + peer pubkey + SDP, and
4. receive the forwarded, signed backstage grant.

Session tickets (M2) authorize *the technician*; nothing authorizes *the agent*. The control plane
already pins `machine.pubkey` at `POST /enroll/redeem` and mints `machine.device_id` server-side
(0007/0008), and `crates/crypto/src/identity.rs` already holds an Ed25519 identity. The missing link
is a proof of possession at registration. This document specifies it.

**M3 in one sentence:** a connection enters the agent registry only after it signs a server-chosen
nonce with the private half of the key the control plane pinned for that device id.

---

## 2. Handshake

### 2.1 State machine (per WebSocket connection)

```
                    ┌──────────────┐
  ws upgrade  ────▶ │  ANONYMOUS   │
                    └──────┬───────┘
                           │ register_agent
             ┌─────────────┴──────────────┐
   dev mode  │                            │  enforced mode
             ▼                            ▼
       Registry.Register            issue agent_auth_challenge
       send `registered`            store pending{nonce,device,pubkey,exp}
             │                            │
             ▼                     ┌──────┴───────┐
       ┌───────────┐               │ AWAITING_PROOF│
       │ REGISTERED│               └──────┬────────┘
       └───────────┘                      │ agent_auth_response
                            ┌─────────────┼─────────────┐
                     valid  │             │ invalid     │ (nothing ever arrives)
                            ▼             ▼             ▼
                   Registry.Register   send `rejected`  stays AWAITING_PROOF
                   send `registered`   CLOSE socket     forever; never enters
                            │                           the registry; socket stays
                            ▼                           open and usable
                     ┌───────────┐
                     │ REGISTERED│
                     └───────────┘
```

Normative consequences — implement each explicitly, each gets a test:

- **A registration that never completes MUST NOT displace an incumbent.** In enforced mode
  `Registry.Register` is called **only** on the valid-proof edge. An `ANONYMOUS`/`AWAITING_PROOF`
  peer is never in the registry, so `Broker.ConnectRequest` can never resolve to it and
  `Registry.Register`'s incumbent-closing branch is never reached on its behalf.
- **Displacement after a valid proof is allowed and intended.** A reconnecting agent proves
  possession of the same pinned key, so closing the stale socket is correct (existing behaviour).
- A peer in `ANONYMOUS`/`AWAITING_PROOF` MAY still send `connect_request`, `sdp`, `candidate`.
  This is what keeps controllers working (see §2.6). `heartbeat` from such a peer returns the
  existing `rejected{reason:"heartbeat for unregistered device"}`.
- An **invalid** proof closes the connection. A **missing** proof does not. Controllers never
  answer the challenge; closing them would break every viewer.

### 2.2 Nonce

| Property | Value |
|---|---|
| Size | exactly **32 bytes** |
| Source | `crypto/rand.Read` (Go). Any read error ⇒ send `rejected`, close, log. Never fall back to a weaker source. |
| Wire encoding | lowercase hex, 64 chars |
| TTL | **30 seconds** (`agentAuthChallengeTTL`) |
| Scope | stored on the `*Peer` (`pendingAuth`), never in a global map |
| Single-use | cleared the moment an `agent_auth_response` is processed, **before** verification, whatever the outcome |
| Concurrency | at most **one** outstanding challenge per connection; a second `register_agent` replaces it and kills the previous nonce |
| Abuse cap | at most **5** `register_agent` messages per connection (`maxRegisterAttempts`); the 6th ⇒ `rejected` + close |

A `register_agent` on a connection that is already `REGISTERED` is answered with
`rejected{reason:"already registered"}` and otherwise ignored — the connection keeps its existing
registration. This removes any "re-register to re-open the auth window" trick.

### 2.3 New messages

Tag convention is unchanged: internally tagged, `"type"` is snake_case, ids are plain JSON strings.

**Server → client — `agent_auth_challenge`**

```json
{
  "type": "agent_auth_challenge",
  "device": "9f1c2c3a-4b5d-4e6f-8091-a2b3c4d5e6f7",
  "nonce": "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
  "expires_at_ms": 1730000030000
}
```

`device` echoes the device id from the `register_agent` that produced the challenge (so a client
juggling reconnects can tell which registration it answers). `expires_at_ms` is informational —
the server clock is authoritative.

**Client → server — `agent_auth_response`**

```json
{
  "type": "agent_auth_response",
  "device": "9f1c2c3a-4b5d-4e6f-8091-a2b3c4d5e6f7",
  "nonce": "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
  "sig": "b8ba…f601"
}
```

`sig` is the hex-encoded 64-byte Ed25519 signature over the canonical preimage of §3.

Go (`server/signaling/messages.go`) — add to the payload types, to `clientTag`/`serverTag`, and to
both `UnmarshalJSON` switches:

```go
type AgentAuthChallenge struct {
    Device      string `json:"device"`
    Nonce       string `json:"nonce"`
    ExpiresAtMs int64  `json:"expires_at_ms"`
}

type AgentAuthResponse struct {
    Device string `json:"device"`
    Nonce  string `json:"nonce"`
    Sig    string `json:"sig"`
}
```

Rust (`crates/protocol/src/signaling.rs`):

```rust
// ClientToServer
AgentAuthResponse { device: DeviceId, nonce: String, sig: String },

// ServerToClient
AgentAuthChallenge { device: DeviceId, nonce: String, expires_at_ms: i64 },
```

Rust **also** gains the `tenant` field that Go's `RegisterAgent` already has and Rust is missing
today (existing, unflagged drift):

```rust
RegisterAgent {
    device: DeviceId,
    pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
    nat: NatType,
    enrollment_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    os: Option<String>,
},
```

`tenant` on the wire is **advisory only**. In enforced mode signaling overwrites `Peer.Tenant` with
the tenant returned by the control plane (§4) and ignores the declared value. Keep sending it: it
is what dev mode uses and it keeps the two languages' structs aligned.

`os` (added with the presence-driven `machine.os` refresh) is **advisory inventory, never
identity**: the agent's current composed OS description — the same string `enroll_once` sends —
optional on the wire (older agents and controllers omit it; `omitempty` both sides). Signaling
**bounds it on receipt** (255 bytes, truncated at a rune boundary — `boundOSDescription`; a live
connection is never refused over an inventory string), carries it through `pendingAuth` into the
registration on both the dev and enforced paths, and re-emits it in `GET /internal/presence`
(`os`, omitted when empty). The control plane then refreshes `machine.os` for the tenant's OWN
rows only, where the value actually differs (`MachineStore.RecordObservedOS`; RLS is the tenant
filter, the same posture as `TouchLastSeen`). Unlike tenant/pubkey there is no authoritative copy
to overwrite it with — the device that proved possession is the authority on what OS it runs.

The TS viewer (`web/viewer/src/lib/protocol.ts`) needs **no change** — the browser is only ever a
controller, and both the Rust and TS signaling clients already skip server messages whose `type`
they do not recognise.

### 2.4 Verification, in order

On `agent_auth_response`, signaling MUST check, in this order, stopping at the first failure:

1. A `pendingAuth` exists on this connection. (No challenge outstanding ⇒ fail.)
2. Take and clear `pendingAuth` (single-use, regardless of outcome).
3. `now <= pending.expiresAtMs`.
4. `msg.Device == pending.Device` (exact string compare).
5. `msg.Nonce` decodes as hex to exactly 32 bytes and equals `pending.Nonce`
   (`subtle.ConstantTimeCompare`).
6. `msg.Sig` decodes as hex to exactly 64 bytes.
7. Resolve the device identity (§4). Any resolver error, 404, or empty pinned pubkey ⇒ fail.
8. `strings.EqualFold(pending.Pubkey, identity.Pubkey)` — the pubkey the client announced at
   `register_agent` must be the pinned one. (Defence in depth; step 9 is the real gate.)
9. `ed25519.Verify(pinnedPubkey, agentAuthSigningBytes(pending.Device, identity.TenantID,
   nonce), sig)`.

On success: set `self.Tenant = identity.TenantID` (**authoritative**, overwriting anything the
client declared), set `self.Pubkey = identity.Pubkey` (canonical lowercase hex),
`s.reg.Register(self)`, send `registered{server_pubkey}`.

On failure: send `rejected{reason: "registration not authorized"}` — **the same generic string for
every failure mode** — log the specific cause server-side only, then close the connection. This
mirrors `ticket.go`'s `errTicketInvalid` posture: a prober must not learn whether the device exists,
whether the pubkey matched, or whether the signature was bad.

### 2.5 Identity-lookup timing

The control-plane lookup happens at **`agent_auth_response`** time, never at `register_agent` time.
Consequences, all intended:

- Controllers (which never answer a challenge) cost zero control-plane calls.
- `register_agent` cannot be used as a device-existence oracle — the reply is a challenge either
  way, with a nonce that carries no information about the device.

### 2.6 Controllers

Controllers use the same `register_agent` message today (Rust `Role::Controller` in
`crates/transport-webrtc/src/lib.rs`, and `web/viewer/e2e/harness.ts`) purely so the broker has a
non-empty `peer_device` to echo. Under this contract, in enforced mode they simply never become
registry entries. Nothing depends on that: `Registry.Lookup` is only consulted for
`connect_request` *targets* and `heartbeat`, and the self-connect guard uses pointer identity.

`Brokered.peer_device` / `peer_pubkey` for the requester side therefore remain **client-asserted and
untrusted**. That is unchanged from today and out of scope for M3 — the technician's authority comes
from the M2 session ticket, not from that echo. Do not "fix" it as a side effect.

---

## 3. Canonical signing bytes — `RMTAGENTAUTHv1`

Same style as `RMTGRANTv1` (grant.go) and `RMTTICKETv1` (ticket.go): a fixed domain tag, a u8
version, then length-prefixed fields, all integers big-endian.

### 3.1 Domain tag

ASCII `RMTAGENTAUTHv1` (14 bytes) followed by **two** `0x00` bytes = **16 bytes**:

```
524d544147454e544155544876310000
```

Distinct from `RMTGRANTv1\x00\x00` and `RMTTICKETv1\x00` at byte 3, so no preimage under one tag can
ever verify as another.

### 3.2 Layout

```
offset  size  field
------  ----  --------------------------------------------------------------
     0    16  domain tag (above)
    16     1  u8  version = 0x01
    17     4  u32 BE  len(device_id) in bytes
    21     N  device_id, UTF-8, no NUL terminator
  21+N     4  u32 BE  len(tenant_id) in bytes
  25+N     M  tenant_id, UTF-8
25+N+M     4  u32 BE  len(nonce) — MUST be 32
29+N+M    32  nonce, raw bytes (NOT hex)
------  ----
 total = 61 + N + M
```

- `device_id` and `tenant_id` are the **server-side authoritative** values: the device id the
  challenge was issued for, and the tenant the control plane reports for it. Not what the client
  declared.
- The nonce is length-prefixed (rather than fixed-width) purely for style consistency with
  `lpStr`; the verifier still MUST reject any length other than 32.
- No timestamp is signed. The nonce's server-side TTL is the freshness bound; a client-chosen
  timestamp would add a clock-skew failure mode and no security.

### 3.3 Golden vector — MANDATORY, pinned in two places

`control-plane/ticket_test.go` and `server/signaling/ticket_test.go` pin the same ticket fixture so
encoder drift breaks a test loudly. Do exactly that here. The control plane does **not** verify
agent-auth signatures, so there are exactly **two** copies:

| Copy | Owner | File |
|---|---|---|
| Rust | R | `crates/protocol/src/agent_auth.rs` (`#[cfg(test)] mod tests`) |
| Go | S | `server/signaling/agentauth_test.go` |

Fixture:

| Input | Value |
|---|---|
| Ed25519 seed (hex) | `0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20` |
| Public key (hex) | `79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664` |
| `device_id` | `9f1c2c3a-4b5d-4e6f-8091-a2b3c4d5e6f7` |
| `tenant_id` | `11111111-2222-3333-4444-555555555555` |
| `nonce` (hex) | `a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf` |

Expected outputs (preimage is 133 bytes):

```
preimage_hex (5 lines of 64 hex chars, last line short — concatenate with no separator):
  524d544147454e544155544876310000010000002439663163326333612d3462
  35642d346536662d383039312d61326233633464356536663700000024313131
  31313131312d323232322d333333332d343434342d3535353535353535353535
  3500000020a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9ba
  bbbcbdbebf

sig_hex:
  b8ba719cba0e4301aba3d1d83b811eead5806461d7cd3633e3f27ae4cd15ecbb
  5480493e0eee099eb64234214f1fd874b5dafa95fc6d31ad2267788d2352f601
```

The single-line values (use these verbatim; the wrapping above is cosmetic):

- preimage:
  `524d544147454e544155544876310000010000002439663163326333612d346235642d346536662d383039312d6132623363346435653666370000002431313131313131312d323232322d333333332d343434342d35353535353535353535353500000020a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf`
- signature:
  `b8ba719cba0e4301aba3d1d83b811eead5806461d7cd3633e3f27ae4cd15ecbb5480493e0eee099eb64234214f1fd874b5dafa95fc6d31ad2267788d2352f601`

Each copy MUST assert **both**: (1) the built preimage hex equals `preimage_hex`, and (2) signing it
with the seed yields `sig_hex` (Rust) / verifying `sig_hex` against the public key succeeds (Go).
Each file carries the same header comment `ticket_test.go` carries: *do not change a value here
without changing it identically there.*

### 3.4 Where the builder lives

- **Rust:** new module `crates/protocol/src/agent_auth.rs`, `pub fn agent_auth_signing_bytes(device:
  &str, tenant: &str, nonce: &[u8; 32]) -> Vec<u8>`. `rmt-protocol` gains `hex = "0.4"` as a
  dependency and `rmt-crypto = { path = "../crypto" }` as a **dev-dependency** (for the golden
  vector only — `rmt-crypto` does not depend on `rmt-protocol`, so this is acyclic).
- **Go:** new file `server/signaling/agentauth.go`, `func agentAuthSigningBytes(deviceID, tenantID
  string, nonce []byte) []byte`. Standard library only.

---

## 4. How signaling learns the pinned pubkey

**DECISION: (a) — a control-plane lookup endpoint.** Rejected alternative and rationale in §7.

### 4.1 Control-plane endpoint (owner C)

```
GET /internal/devices/{device_id}/identity
Authorization: Bearer <service token>
```

- Mounted on the **root** mux in `Server.Handler()`, beside `POST /enroll/redeem` — outside the
  auth → tenant (RLS) chain, because signaling is not a tenant principal and the lookup is
  deliberately cross-tenant (`device_id` is globally unique since 0008).
- Mounted **only** when `s.DeviceIdentityToken != "" && s.Machines != nil`. Unset ⇒ the route does
  not exist ⇒ 404. There is no unauthenticated mode.
- New `Server` field: `DeviceIdentityToken string` (production reads env `CP_DEVICE_IDENTITY_TOKEN`
  in the binary's wiring; the field itself is what handlers use). Reject a configured token shorter
  than 32 characters at wiring time.
- Token comparison uses `subtle.ConstantTimeCompare`. Missing/malformed/wrong ⇒
  `401 {"error":"unauthorized"}`.
- Throttled like `/enroll/redeem`: `keys := []string{ipKey("device-identity", clientIP(r))}`,
  `th.Allow` before the store call, `th.Fail` on 401/404, `th.Reset` on 200.
- **Not** recorded in the management audit trail. It is a read on a hot path (every agent
  reconnect); auditing it would drown the trail. State that in the handler comment.

Responses:

| Case | Status | Body |
|---|---|---|
| Found, pubkey pinned | 200 | `{"device_id":"…","tenant_id":"…","pubkey":"<64 lowercase hex>"}` |
| Unknown device id | 404 | `{"error":"unknown device"}` |
| Found but `pubkey` empty (legacy `POST /enroll` machines) | 404 | `{"error":"unknown device"}` |
| Bad/missing token | 401 | `{"error":"unauthorized"}` |
| Store failure | 500 | `{"error":"could not resolve device identity"}` |

A machine with no pinned key is **unauthenticatable, by design** — it fails closed rather than
falling back to trust. Re-enroll such machines through `POST /enroll/redeem`.

Why this is not a fleet-enumeration oracle: the route requires a 32+ char shared secret; device ids
are server-minted UUIDv4 (0008 / `handleRedeemEnrollment`) so guessing is infeasible; failures are
throttled per source; and the response reveals nothing beyond what a holder of the secret — the
signaling server — must already know.

### 4.2 Persistence (owner C)

- `MachineStore` gains:
  ```go
  // LookupDeviceIdentity resolves a device id to its tenant + pinned pubkey ACROSS TENANTS.
  // Pre-tenant, like RedeemToken: signaling has no tenant context. ErrMachineNotFound when the
  // device id is unknown OR has no pinned pubkey.
  LookupDeviceIdentity(ctx context.Context, deviceID string) (*DeviceIdentity, error)
  ```
  ```go
  type DeviceIdentity struct {
      DeviceID string `json:"device_id"`
      TenantID string `json:"tenant_id"`
      Pubkey   string `json:"pubkey"` // lowercase hex, 64 chars
  }
  ```
- `InMemoryMachineStore`: scan all tenants; return `ErrMachineNotFound` when absent or `Pubkey == ""`.
  **The permissive (dev) store MUST NOT synthesize here** — a permissive identity oracle would hand
  an attacker a valid identity for any device id and defeat the entire milestone. Assert this in a
  test.
- `PgMachineStore`: calls the new SECURITY DEFINER function below (RLS blocks a tenant-less
  `SELECT`), on the pool directly — not `withTenant`.

### 4.3 Migration `0010_device_identity.sql` (owner C)

**0010 is the next free number.** Follow 0007's posture exactly: `SECURITY DEFINER`, pinned
`search_path`, `GRANT EXECUTE … TO PUBLIC`, with a header comment explaining why the RLS bypass is
necessary and why it is safe.

```sql
CREATE FUNCTION cp_machine_identity_by_device_id(p_device_id text)
    RETURNS TABLE (device_id text, tenant_id uuid, pubkey bytea)
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT m.device_id, m.tenant_id, m.pubkey
    FROM machine m
    WHERE m.device_id = p_device_id
      AND m.pubkey IS NOT NULL
$$;

GRANT EXECUTE ON FUNCTION cp_machine_identity_by_device_id(text) TO PUBLIC;
```

At most one row: `machine.device_id` is globally unique as of 0008. Test-harness obligations:

- add `DROP FUNCTION IF EXISTS cp_machine_identity_by_device_id(text);` to `resetSchema`'s DROP list
  in `control-plane/pgstore_test.go` (mandatory for **any** new `cp_*` function);
- add an `applyDeviceIdentityMigration(t, pool)` helper following the existing
  `applyEnrollmentMigration` shape, and call it from the tests that need it (it depends on 0008
  having been applied — apply `applyMachineDeviceUniqueMigration` first).

### 4.4 Signaling client + cache (owner S)

New file `server/signaling/deviceidentity.go`. Standard library only (`net/http`, `encoding/json`).

```go
type DeviceIdentity struct {
    DeviceID string `json:"device_id"`
    TenantID string `json:"tenant_id"`
    Pubkey   string `json:"pubkey"`
}

// IdentityResolver resolves a device id to its control-plane-pinned identity.
// ErrDeviceUnknown for a 404; any other error is a transport/config failure.
type IdentityResolver interface {
    Resolve(ctx context.Context, deviceID string) (*DeviceIdentity, error)
}
```

| Concern | Rule |
|---|---|
| Base URL | env `SIGNALING_DEVICE_IDENTITY_URL`, e.g. `https://cp.example:8443`. Request path is `<base>/internal/devices/<url-escaped device id>/identity`. |
| Token | env `SIGNALING_DEVICE_IDENTITY_TOKEN`, sent as `Authorization: Bearer …` |
| Timeout | 5 s per request (`http.Client{Timeout: 5 * time.Second}`) |
| Positive cache | 60 s TTL, keyed by device id |
| Negative cache (404) | 10 s TTL — bounds the damage of a burst of bogus device ids without pinning a stale "unknown" across a real enrollment |
| Cache cap | 4096 entries; on overflow drop the whole map (cheap and correct; an LRU is optional, not required) |
| Errors (timeout, 5xx, 401, malformed body) | **never cached**, registration rejected |
| Response validation | `pubkey` MUST decode as hex to 32 bytes and `tenant_id` MUST be non-empty; otherwise treat as a transport failure |

**Control plane unreachable ⇒ fail closed.** New registrations are rejected for as long as the
control plane is down. Already-registered agents are unaffected — their sockets are live and their
registry entries persist — so a control-plane outage does not drop existing sessions; it only stops
new agents from coming online. Stale cache entries are **not** served past their TTL. Do not add a
"grace mode".

---

## 5. First-run enrollment (owner R)

Today `HelperConfig::ensure_device_id` invents a random UUID locally, `config.template.json` ships
`"device_id": ""`, and nothing ever redeems a token. Under this contract the device id is
**server-minted** and arrives from `POST /enroll/redeem`.

### 5.1 Flow

```
agent_host.exe enroll --control-plane-url <URL> --token <ENROLLMENT_TOKEN> [--name <hostname>]
```

1. Load `identity.key` if present, else `Identity::generate()`.
2. `POST <URL>/enroll/redeem` with
   `{"token":"<tok>","pubkey":"<identity.public_hex()>","name":"<hostname>","os":"<os_description()>"}`.
   Do **not** send `device_id` — the field is deprecated and ignored server-side. (`os` seeds
   `machine.os` at enrollment; the presence-driven refresh in §2.3 is what keeps it true after OS
   upgrades.)
3. On `201`, read `{"machine":{"id":…,"tenant_id":…,"device_id":…,"pubkey":…}}`. Assert the returned
   `pubkey` equals our own hex (defence against a mis-provisioned control plane); abort if not.
4. Persist, in this order (key first — a crash between the two must never leave a device id with no
   key):
   - `C:\rmt-agent\identity.key` — 64 lowercase hex chars, the Ed25519 **seed**
     (`Identity::seed()`), no BOM.
   - `config.json` — set `device_id`, `tenant_id`; **clear `enrollment_token`** (single-use secret,
     it must not linger on disk).
5. Tighten the ACL on `identity.key` immediately after writing, from Rust, by invoking
   `icacls <path> /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)"`. Log loudly if it
   fails; do not silently continue with a world-readable private key. (Doing it in Rust rather than
   in the installer is deliberate — see §8.3.)
6. Non-2xx: print the status and body, exit non-zero. Never fall back to a self-invented device id.

The per-session helper runs the *same* `enroll_once()` at startup when `device_id` is empty **and**
both `control_plane_url` and `enrollment_token` are set (this covers image-based deployments where
the installer could not reach the control plane). It attempts it once per start; on failure it logs
and falls back to the existing capture-proof loop.

TLS: `reqwest` with `rustls-tls`, certificate validation **on**. `danger_accept_invalid_certs` is
banned. A `control_plane_url` with scheme `http://` is permitted only for `localhost`/`127.0.0.1`
and MUST log a warning; any other `http://` URL is a hard error.

### 5.2 `HelperConfig` (`crates/agent-windows/src/config.rs`)

New fields, all `Option<String>` with `#[serde(default)]` so existing configs still parse:

| Key | Meaning |
|---|---|
| `control_plane_url` | Control-plane base URL used for enrollment. Absent ⇒ no enrollment; dev behaviour (§6). |
| `enrollment_token` | One-shot bearer secret. **Cleared after successful redemption.** |
| `tenant_id` | Written by redemption. Required to build the §3 preimage. |
| `identity_path` | Override for `C:\rmt-agent\identity.key` (tests). Absent ⇒ the default. |

`device_id` keeps its type and meaning but is no longer client-chosen. **`ensure_device_id` is
replaced** by:

```rust
/// Returns the enrolled device id. NEVER invents one when the agent is control-plane managed:
/// device ids are minted server-side at redemption (control-plane/http.go handleRedeemEnrollment).
///
///   Some(id)                                  -> use it
///   None + control_plane_url configured       -> None; caller must enroll (or stay in proof mode)
///   None + no control_plane_url (dev/e2e)     -> generate + persist a random UUID, as before
pub fn device_id_or_dev_fallback(&mut self) -> Option<String>
```

The dev branch is what keeps `browser-agent.spec.ts` and the loopback integration tests working
unchanged. Keep the existing `ensure_device_id` tests' intent; do not delete assertions.

### 5.3 Config template and installer (specified here, landed later)

`dist/agent/config.template.json` and `dist/agent/install-agent.ps1` are **generated by
`scripts/build-release.ps1`**, and `dist/` plus that script are frozen for this change. The required
content is specified here so the packaging pass is mechanical; **no implementer edits `dist/` or
`scripts/build-release.ps1` under this contract.** Track it as the M3 packaging follow-up.

Template becomes:

```json
{
  "signaling_url": "ws://YOUR-SIGNALING-HOST:8080/ws",
  "control_plane_url": "https://YOUR-CONTROL-PLANE:8443",
  "enrollment_token": "",
  "device_id": "",
  "tenant_id": "",
  "stun": [],
  "transfer_dir": "C:\\rmt-agent\\transfers",
  "grant_issuer_pubkey": ""
}
```

`install-agent.ps1` must:

- accept `-ControlPlaneUrl <string>` and `-EnrollmentToken <string>` (both required together);
- write `control_plane_url` / `enrollment_token` into `config.json` and write `device_id: ""`;
- **stop auto-generating a GUID device id** (`if ([string]::IsNullOrWhiteSpace($DeviceId)) { $DeviceId = [guid]::NewGuid() … }` is deleted). `-DeviceId` remains accepted **only** when
  `-ControlPlaneUrl` is absent (the LAN/dev path) and warns that the agent will not be
  control-plane-authenticated;
- run `agent_host.exe enroll --control-plane-url … --token …` **before** `agent_host.exe install`,
  and abort the install on a non-zero exit;
- warn (as it does for a blank `grant_issuer_pubkey`) when `-ControlPlaneUrl` is omitted.

### 5.4 Agent registration path

`crates/transport-webrtc/src/lib.rs`:

```rust
pub enum Role {
    Controller { target: DeviceId },
    Agent {
        device: DeviceId,
        pubkey: String,
        /// Tenant from enrollment. Required to answer an `agent_auth_challenge`.
        tenant: Option<String>,
        /// Signs the §3 preimage. `None` ⇒ dev/unauthenticated agent (challenges go unanswered).
        signer: Option<Arc<dyn ChallengeSigner>>,
    },
}

/// Signs an agent-auth preimage with the agent's long-term Ed25519 key. Kept as a trait so this
/// crate needs no key material and no crypto dependency.
pub trait ChallengeSigner: Send + Sync {
    fn sign(&self, preimage: &[u8]) -> [u8; 64];
}
```

In `connect_inner`'s wait loop, add one arm before the `Brokered`/`Rejected` arms:

```rust
ServerToClient::AgentAuthChallenge { device, nonce, .. } => {
    // Sign and answer; on any local failure just keep waiting — the connect timeout is the bound.
    // Never fabricate a signature.
}
```

- Decode `nonce` from hex; require exactly 32 bytes.
- Build the preimage with `rmt_protocol::agent_auth::agent_auth_signing_bytes(&device.to_string(),
  tenant.as_deref().unwrap_or(""), &nonce)`.
- Send `ClientToServer::AgentAuthResponse { device, nonce, sig: hex::encode(sig) }`.
- `Role::Controller` ignores the challenge entirely.

`crates/agent-windows/src/host.rs` currently passes `pubkey: "ed25519:rmt-agent"` — a placeholder.
It MUST now pass the real `identity.public_hex()` (bare 64-char lowercase hex, **no `ed25519:`
prefix** — `machine.pubkey` stores bare hex and §2.4 step 8 compares against it), plus the
configured `tenant_id` and a `ChallengeSigner` backed by `rmt_crypto::Identity`.

The agent MUST NOT send `heartbeat` until it has received `registered`. On
`rejected{reason:"registration not authorized"}` it closes and retries through the existing
reconnect loop with backoff (≥5 s, capped at 60 s, jittered) — a tight retry loop would hammer the
control plane through the resolver.

---

## 6. Backward compatibility and dev mode

### 6.1 The switch

| | |
|---|---|
| Flag | `-insecure-no-agent-auth` (bool) |
| Default | **`false`** — enforcement ON |
| Effect when set | `register_agent` registers immediately and replies `registered`, exactly as today. No challenge is issued, no identity resolver is constructed, no control plane is contacted. |
| Startup rule | If `SIGNALING_DEVICE_IDENTITY_URL` **or** `SIGNALING_DEVICE_IDENTITY_TOKEN` is empty and the flag was not passed ⇒ `log.Fatalf`. |
| Noise when set | one `log.Printf("WARNING: …")` at startup, in the wording style of the existing ticket warning |

Flag help text (verbatim style of the existing one):

```
"LOCAL DEV ONLY: accept register_agent without proof of possession of the enrolled agent key — "
"ANY WebSocket client can then displace ANY agent"
```

Fatal message (verbatim style of the existing one):

```
SIGNALING_DEVICE_IDENTITY_URL/SIGNALING_DEVICE_IDENTITY_TOKEN are not set: register_agent could
not be authenticated, so ANY WebSocket client could displace ANY agent and receive its brokered
sessions. Point them at the control plane's device-identity endpoint, or pass
-insecure-no-agent-auth for local development.
```

This is a **separate** flag from `-insecure-no-ticket-verification`. Do not couple them and do not
let one imply the other: they gate different halves (who may reach an agent vs. who may *be* an
agent), and a deployment that gets one right must not silently inherit the other's opt-out.

### 6.2 The Playwright specs

All five specs spawn signaling as `spawn(SIGNALING_EXE, ["-insecure-no-ticket-verification"], …)`.
Each becomes:

```ts
spawn(SIGNALING_EXE, ["-insecure-no-ticket-verification", "-insecure-no-agent-auth"], …)
```

in `backstage.spec.ts:88`, `browser-agent.spec.ts:98`, `console.spec.ts:89`,
`secure_grant.spec.ts:150`, `transfer.spec.ts:102`. **That is the only permitted edit to those
files** under this contract (owner S — see §8).

With both flags set, `browser-agent.spec.ts`'s real Rust agent behaves exactly as today: it has no
`control_plane_url`, so `device_id_or_dev_fallback` generates a local id, it registers, and it is
acked with `registered` without any challenge. The browser controller is unaffected either way.

### 6.3 What is NOT optional

Enforcement is off only when an operator types `-insecure-no-agent-auth` on the command line. There
is no environment variable that disables it, no "auto-detect", and no degradation to permissive mode
when the control plane is unreachable (§4.4).

---

## 7. Rejected alternatives

**(b) A control-plane-signed device certificate the agent presents.** The control plane would mint,
at `POST /enroll/redeem`, a signed blob binding `device_id + tenant_id + pubkey`, the agent would
store it and present it in `register_agent`, and signaling would verify it with a key it already
holds. Tempting: no new endpoint, no cache, no runtime dependency on control-plane availability.

Rejected because (1) it introduces a **second** cross-language canonical preimage with its own golden
vector to keep byte-identical — the exact drift surface this project has been paying down; (2) the
certificate is a long-lived credential with **no revocation** — decommissioning a machine, or
recovering from a stolen agent key, would require a CRL or a short-TTL renewal protocol we would
have to build anyway; and (3) `machine.pubkey` would stop being the single source of truth, since a
still-valid certificate would out-vote the current database row. The lookup endpoint reuses the
truth the control plane already pins, revokes instantly (delete the machine, or clear its pubkey),
and its cost is ordinary parts: one HTTP GET, one bearer token, one TTL cache. The trade-off
accepted: rendezvous now depends on control-plane availability for **new** registrations, bounded by
a 60 s positive cache and by existing registrations being unaffected.

**Signing the challenge with the session ticket key.** No — the ticket key is the control plane's,
not the agent's; it would prove nothing about the agent.

**Requiring the enrollment token on every `register_agent`.** The `enrollment_token` field already
on the wire is a bearer secret that would then be replayable forever and readable from agent
configuration on every managed machine. Proof of possession of a non-exportable-in-principle private
key is strictly stronger. The field stays where it is and stays unused by signaling.

**Assigning controllers a server-side peer id.** Would fix the untrusted `Brokered.peer_device`
echo, but it is a separate concern with its own compatibility surface (§2.6). Out of scope.

---

## 8. Work split

Ownership is exclusive. If a file is not on your list, do not edit it — including tests.

### 8.1 R — Rust (`crates/**`, agent)

- `crates/protocol/Cargo.toml` — add `hex`; add dev-dep `rmt-crypto`.
- `crates/protocol/src/lib.rs` — declare `pub mod agent_auth;`.
- **`crates/protocol/src/agent_auth.rs` (new)** — canonical builder + golden vector (§3).
- `crates/protocol/src/signaling.rs` — `AgentAuthResponse`, `AgentAuthChallenge`, `tenant` on
  `RegisterAgent`.
- `crates/transport-webrtc/src/lib.rs` — `Role::Agent` fields, `ChallengeSigner`, challenge arm.
- `crates/transport-webrtc/Cargo.toml` — add `hex`.
- `crates/agent-windows/src/config.rs` — new keys, `device_id_or_dev_fallback`.
- **`crates/agent-windows/src/enroll.rs` (new)** — `enroll_once()`, identity load/generate/persist,
  ACL tighten.
- `crates/agent-windows/src/host.rs`, `.../service.rs`, the `agent_host` binary — the `enroll`
  subcommand, real pubkey, signer wiring, heartbeat gating, reconnect backoff.
- `crates/agent-windows/Cargo.toml` — add `reqwest` (`default-features = false`, features
  `["rustls-tls","json","blocking"]`), `hex`.
- `crates/crypto/src/identity.rs` — only if a `ChallengeSigner` impl is convenient there.
- `docs/10-deployment.md` — agent install/enrollment section.

### 8.2 S — Go signaling (`server/signaling/**`)

- **`server/signaling/agentauth.go` (new)** — `agentAuthSigningBytes`, `pendingAuth`, nonce
  minting, the §2.4 verification.
- **`server/signaling/agentauth_test.go` (new)** — golden vector + handshake/state-machine tests.
- **`server/signaling/deviceidentity.go` (new)** — `IdentityResolver`, HTTP client, cache.
- **`server/signaling/deviceidentity_test.go` (new)** — cache TTLs, fail-closed on 5xx/timeout,
  negative caching, no stale serving.
- `server/signaling/messages.go` — the two payload structs, tags, both decode switches.
- `server/signaling/main.go` — flag, env parsing, fail-closed startup, `dispatch` arms, `Server`
  wiring.
- `server/signaling/registry.go` — only if a comment needs to record that `Register` is now reached
  solely on the proven path. No behavioural change is required here.
- `server/signaling/main_test.go`, `messages_test.go` — updates for the above.
- `web/viewer/e2e/{backstage,browser-agent,console,secure_grant,transfer}.spec.ts` — **the spawn-arg
  line only** (§6.2). Nothing else in `web/**`.

### 8.3 C — Go control-plane (`control-plane/**`)

- `control-plane/machine.go` — `DeviceIdentity`, `LookupDeviceIdentity` on the interface + the
  in-memory store (permissive store must **not** synthesize).
- `control-plane/pgstore.go` — `PgMachineStore.LookupDeviceIdentity` via the new function, on the
  pool (not `withTenant`).
- **`control-plane/migrations/0010_device_identity.sql` (new)**.
- `control-plane/http.go` — `DeviceIdentityToken` field, route mount, `handleDeviceIdentity`.
- `control-plane/pgstore_test.go` — the `resetSchema` DROP addition + `applyDeviceIdentityMigration`.
- `control-plane/machine_test.go`, `machine_pgstore_test.go`, `http_test.go` — coverage for the
  above (found / unknown / no-pinned-pubkey / bad token / throttled / permissive-store-refuses).

### 8.4 Contested files — resolved

| File | Assigned to | Note |
|---|---|---|
| `web/viewer/e2e/*.spec.ts` | **S** | spawn args only; R and C do not touch `web/**` |
| `web/viewer/src/lib/protocol.ts` | **nobody** | no TS change is required (§2.3) |
| `docs/10-deployment.md` | **R** | S and C document their env vars *inside* their own code comments, not here |
| `docs/11-agent-identity-contract.md` | **nobody** | this file is frozen for the implementation pass |
| `dist/**`, `scripts/build-release.ps1` | **nobody** | frozen; §5.3 is the deferred packaging spec |
| `docs/07-session-handoff.md` | **nobody** | follow-up pass after all three land |
| golden-vector constants | **R and S**, one copy each | intentional duplication, separate files (§3.3) |

### 8.5 Integration order

R, S and C can develop in parallel against this document. The end-to-end path only closes when all
three land, so verify in this order:

1. **C** first — `applyDeviceIdentityMigration` + endpoint tests green against the live Postgres
   (`TEST_DATABASE_URL=…`, without it the pgx tests skip).
2. **S** — golden vector matches §3.3, resolver tests green, e2e specs still pass with both dev
   flags.
3. **R** — golden vector matches §3.3 byte-for-byte against S's, then a live agent registers against
   a signaling server started **without** `-insecure-no-agent-auth` and pointed at a running
   control plane.

### 8.6 Definition of done

- Both golden-vector tests pin the identical constants from §3.3 and pass.
- Signaling started without `-insecure-no-agent-auth` and without the identity env vars **exits**.
- A client that sends `register_agent` for an enrolled device and never answers the challenge does
  **not** appear in the registry and does **not** close the incumbent's socket — asserted by a test.
- A client that answers with a signature from the wrong key is rejected with the generic reason and
  disconnected — asserted by a test.
- A real agent, freshly enrolled via `agent_host enroll`, registers against an enforcing signaling
  server and a technician can broker a session to it.
- All five Playwright specs pass unchanged apart from the added flag.
- `go vet ./...` clean in both Go modules; `cargo test` green with
  `RUSTFLAGS="-C debuginfo=0" CARGO_INCREMENTAL=0`.
