# docs/63 — Central session-recording storage (design)

docs/01 §2 "Session recording" (P1 `[~]`), §10 "Video + event auditing" (P1 `[~]`), §12 "Compliance/audit
export archives" (P1 `[~]`): recordings exist only on the guest (`C:\rmt-agent\recordings`, IVF, 72 h TTL).
Decided: a writable **volume** on the server (not Postgres blobs); recordings first; per-tenant
retention, size cap, encryption at rest, browser playback for audit-capable roles. Mapped by three read-only
surveys (agent, server/deploy, viewer) before designing.

## 1. What the maps established

- The agent tees encoded VP8 into IVF segments + a JSON sidecar with per-segment sha256; no audio; up to
  1 GiB per recording (~45 min at 3 Mbps); segments can differ in resolution. Attended sessions cannot
  record (by design). `recording_started` / `recording_stopped` (with `segment_sha256[]`) are agent-signed
  audit events on the session chain — but a session that ends abnormally finalizes the file WITHOUT sealing
  a stop event.
- No agent→server upload path exists. The file-transfer channel is 64 MiB, in-memory, transfer-root only,
  not resumable, and needs a live viewer — it fails exactly when the audit story matters (abnormal ends).
- The control plane is stateless: no volume, no filesystem writes, and the protected route chain buffers
  whole bodies (64 KiB default) while pinning a pool connection; server timeouts 30 s read / 60 s write.
- `CapViewAudit` (Owner/Admin/Auditor) gates audit reading, group-scoped via the machine's group.
- Browsers cannot play IVF; there is no muxer anywhere in the repo.
- Backup today = `pg_dump` + `deploy/.env`; docs/22 says recordings live on agents.

## 2. Decisions

**D1 — Transport: the agent SERVICE uploads finished recordings over a new signed, resumable HTTPS API**
(not the session data channel; not live streaming). It works with no viewer, after the session ended, and
across agent restarts.
- Signed request `RMTAGENTUPLOADv1`: domain tag ‖ method ‖ path ‖ tenant ‖ device ‖ recording id ‖ offset
  ‖ sha256(body) ‖ unix-ms timestamp, Ed25519 by the agent's enrolled key, verified against the pinned
  `machine.pubkey` (the same key `verifyAgentAudit` uses). ±5 min window. No nonce store is needed because
  every call is idempotent: a chunk re-PUT at a committed offset with the same hash is a no-op, finish is
  idempotent, and create is keyed by the agent-chosen recording id (unique per machine).
  Golden vectors in Rust and Go.
- Calls: `POST /cp/agent/recordings` (create: recording id, session id, segment list with sizes) →
  201 `{upload state}` | 409-already-complete | 403 `storage_off` (tenant retention 0 — the agent stops
  trying and marks the sidecar "not stored") | 413 over cap | 507 server full (retry later);
  `PUT …/{id}/segments/{n}?offset=` 8 MiB chunks; `HEAD …/{id}/segments/{n}` → committed offset;
  `POST …/{id}/finish` with the per-segment digests.
- Routes are ROOT routes outside the protected chain: authenticate the signature first, stream to a temp
  file with a hard byte cap and per-request read deadline (`http.NewResponseController`), then a short RLS
  transaction to record progress. Never hold a pool connection while receiving bytes.
- When: after a recording is finalized, never while a session is live on that machine, rate-capped
  (default 2 Mbps). Durable queue state lives in the sidecar (upload id, committed offsets); the local 72 h
  sweep skips pending uploads; local files are deleted after the server confirms `complete`.
- No capability negotiation needed: old agents simply never upload; a new agent learns "storage off" from
  the 403 and stops.

**D2 — Integrity.** On finish the server verifies each plaintext segment's sha256 against the digests the
agent signed in the finish call → status `complete`. It additionally looks for the session chain's
`recording_stopped` event with the same digests: found → `verified_with_audit`; absent (abnormal end) →
`agent_attested`, shown as such in the UI (honest, not hidden). `truncated` and `dropped_frames` are stored
and shown. Audit rows outlive blobs; an expired recording reads "expired", never "missing".

**D3 — Storage layout.** `<root>/<tenant_uuid>/<recording_uuid>/<NNNN>.ivf.enc` (evidence copy) and
`<NNNN>.webm.enc` (playback copy, produced at finish). Paths are derived ONLY from database ids; temp
uploads in `<root>/.incoming/<upload_uuid>/` on the same filesystem (atomic rename). Table
`session_recording` (+ `session_recording_segment`): tenant, recording id, session, machine (composite FKs —
a plain FK bypasses RLS on write), status, sizes, digests, truncated/dropped, started/ended, `expires_at`,
key id, matched audit seq. RLS tenant policy.

**D4 — Encryption at rest:** chunked AEAD (XChaCha20-Poly1305, 64 KiB plaintext frames, counter nonce,
final-frame flag), a random per-recording data key wrapped by a master key from a new env var
`RECORDING_MASTER_KEY` (never `GRANT_ISSUER_SEED`), key id in the envelope, rotation command modelled on
`reencrypt-totp`. Fixed frames make range reads (seeking) cheap. Losing the master key = losing every
recording: it joins the must-back-up secrets.

**D5 — Retention and caps (per tenant, default OFF).** `tenant_recording_policy`: `retention_days` 0|1..365
(0 = do not store centrally; UI presets 30/90), `max_recording_bytes` (≤ 1 GiB, the agent's ceiling),
`quota_bytes` (tenant total). Audited PUT; fail-closed naming so a stale full-overwrite client can never
switch storage ON. A sweeper on the existing 5-minute reaper tick (new SECURITY DEFINER lister, not the
0050 one) expires rows then deletes files idempotently; an orphan pass walks `<root>/<tenant>/<recording>`
by NAME (UUID-parsed; anything else is skipped and reported, never deleted) and removes blobs with no live
row or past expiry, plus stale `.incoming`. A server disk-free floor refuses new uploads (507), never
evicts early, and raises the existing health signal.

**D6 — Who may watch.** New `CapViewRecordings` (viewing a screen is more sensitive than reading an audit
list), granted to Owner, Admin, Auditor via a role-preset migration; NOT API-token grantable; NOT held by
Technician (the technician who ran a session does not get to replay it by default). Group-scoped exactly
like backstage audit (`ScopeFor` + `AllowsInGroup` on the machine's group). Every playback start (once
per recording per viewer per 10 min) and every download writes a management audit row.

**D7 — Playback.** At finish the server remuxes each IVF segment to WebM (stream copy, no transcode) with a
Go-native muxer (no ffmpeg on untrusted guest data); the muxer validates IVF headers/frame sizes against
the signed metadata, bounds memory, and is fuzzed. Timestamps keep wall-clock gaps. The console plays a
multi-resolution recording as a playlist of per-segment WebM files through a same-origin, cookie-authed,
range-capable stream endpoint (decrypting frames on the fly). Downloads give the evidence IVF + sidecar +
a manifest with digests.

**D8 — Backup (proposed to the deployment owner).** v1: the recordings volume is OUTSIDE
the backup contract — the retention window is the stated durability, documented loudly in docs/22; the
master key IS in the must-back-up set; the restore drill reconciles rows against blobs (rows with no blob →
`lost`; blobs with no row → orphan pass). Compose gets a named volume (pre-created dir chowned to uid 10001;
`down -v` destroys it — say so), Caddy gets upload/download timeouts and a deliberate body cap on the two
recording paths.

**D9 — Out of scope for v1:** attended-session recording; CLI-broker recordings; enforcing
`require_recording` (still refused at admission until capability negotiation — central storage is NOT
marketed as enforced recording); audio.

## 2a. Independent review — binding contracts; these SUPERSEDE §2 where they differ

- **C1 Signed request.** `RMTAGENTUPLOADv1` preimage = length-prefixed binary fields, in order: domain tag,
  version, deployment audience (the control plane's public origin), operation enum (create | put | head |
  finish), canonical path, tenant id, device id, enrollment key fingerprint (sha256 of the pinned pubkey),
  recording id, upload generation, segment index, offset, exact body length, raw sha256(body), unix-ms
  timestamp. The path carries NO behaviour-changing query parameters (all of the above are headers mirrored
  in the preimage; any query string, duplicate header or non-canonical path → 400). HEAD is signed like any
  other call. The body is streamed to an encrypted temp generation and its sha256/length verified against the
  signed values BEFORE anything is committed. Rust and Go golden vectors, including NEGATIVE vectors (each
  field changed → verify fails).
- **C2 Upload state machine.** `uploading → evidence_complete → (playback_ready | playback_failed) → expired
  → deleted`, plus terminal `abandoned` / `refused`. Create metadata (session, machine, segment count,
  per-segment declared lengths, generation) is immutable; a conflicting create or finish → 409; a create for a
  recording id that has a tombstone (expired/deleted/abandoned) → 410, never a resurrection. Commits are
  serialized per segment (row lock); a PUT is accepted only at the next offset, or as an exact re-send of an
  already-committed chunk (same offset, length, sha256 → 200, no effect). Bytes are fsynced before the DB
  commit that acknowledges them; startup reconciliation resets any segment whose temp file is missing, short, or carries unacknowledged bytes past the DB-committed offset (never truncate-and-overwrite: a frame index is sealed once per nonce prefix, so the segment restarts from 0 under a fresh prefix).
  Retries never extend expiry.
- **C3 Root-route pipeline and resource bounds.** Root routes run their own pipeline: parse + bound headers →
  signature verify against the pinned key with the machine's current enrollment (retired/quarantined
  machines refused) → admission limits (global, per-tenant, per-device concurrency; per-device request rate;
  bounded wait queue; max upload lifetime 24 h) → short scoped DB operations, never a pool connection held
  while bytes flow. Quota is a durable RESERVATION made at create covering both stored copies (IVF + WebM
  at the muxer maximum 1.2×+4 KiB, see §7), AEAD overhead and temp, released on abandon/refusal; the disk-free floor is checked against
  reservations, not instantaneous free space. Chunk size **1 MiB**. Each route sets its own read/write
  deadlines via `http.NewResponseController` (unsupported → fail closed), with a progress deadline as well
  as a total bound; Caddy timeouts for these paths are set to match; tests cover slow clients, disconnects
  and the server-deadline override.
- **C4 Provenance labels.** No "verified" wording. Two labels: **"Agent-signed; matches session audit"** —
  only when an actually SIGNED `recording_stopped` on the accepted chain of the same tenant, session and
  machine, signed by the same enrollment key, has the same ordered digest list AND the same truncation,
  dropped-frame and segment-count metadata (any conflict → the upload is refused, not relabelled); and
  **"Agent-signed; no matching stop event"**. Docs and UI state plainly that whoever controls the endpoint's
  agent key can fabricate either; neither is independent capture verification. Both are playable for
  authorized viewers; completeness/truncation shown separately.
- **C5 Envelope.** Versioned file envelope; header = magic, version, key id, wrapped DEK (wrapped with AAD =
  tenant ‖ recording ‖ key id), tenant, recording, segment, representation (ivf | webm), file generation,
  random 16-byte file nonce prefix, total plaintext length, frame count; header is authenticated (its hash is
  in every frame's AAD). Frames: XChaCha20-Poly1305, nonce = prefix ‖ frame index, AAD = header hash ‖ frame
  index ‖ plaintext length ‖ final flag. A rewrite is a new generation with a new prefix. Full reads require
  the final frame and exact EOF; range reads check the frame index against the authenticated frame count.
  Temp/incoming files are written in the same envelope (never plaintext on disk).
- **C6 Deletion safety.** All filesystem access goes through a trusted root handle (Go `os.Root`), refuses
  symlinks and non-regular files, never crosses mounts. Retention deletion: mark `expired` (durable) → unlink
  → mark `deleted`; failures retry and raise deletion-lag alerts. The orphan pass NEVER deletes: it moves an
  apparent orphan (UUID-named, no live row) into `.quarantine/` with a 14-day grace and a manifest, and is
  DISABLED while the database is unreachable or a restore is in reconciliation mode. The cross-tenant lister
  is a narrow SECURITY DEFINER function with fixed search_path and EXECUTE granted only to the app role.
- **C7 Muxer bounds.** Server-owned limits (segments ≤ 64, frames ≤ 500k/segment, frame ≤ 4 MiB, dimensions
  ≤ 8192×8192, monotonic timestamps within the recording's window, output ≤ 1.2 × input), checked
  arithmetic, exact input consumption; runs in a bounded async worker queue with cancellation and a time
  budget; fuzzed with malformed and amplification inputs. Evidence completeness and playback readiness are
  separate statuses; a muxer failure never affects the evidence copy.
- **C8 Playback authorization.** Every metadata and content route (list, detail, playlist, segment stream,
  range, evidence download) re-checks `CapViewRecordings` + group scope on the machine's CURRENT group (a
  deleted machine → visible only to tenant-wide holders); API tokens rejected everywhere; authorization
  before any conditional response; `Cache-Control: private, no-store`. An audit row is PERSISTED before
  content is released (dedup of "playback started" per recording per viewer per 10 min, server-side across
  all routes; every evidence download audited); audit unavailable → 503, no content.
- **C9 Agent queue bounds.** Pending uploads are bounded by age (7 days), total bytes (5 GiB) and retries
  (exponential backoff); terminal responses (`storage_off`, 410, 413 per-recording) end the upload and are
  recorded in the sidecar and agent log; `storage_off` is evaluated per recording at create time (it is not a
  permanent agent preference). Local deletion only after an acknowledgement that binds recording id,
  generation and the digest list with status `evidence_complete`. Re-enrollment (new key) abandons pending
  uploads explicitly. While pending, the local TTL is extended only up to the 7-day bound.
- **C10 Retention anchor.** `expires_at = server time at evidence_complete + retention_days`; never derived
  from agent timestamps; never extended by retries or replays. Shortening retention applies to existing rows
  on the next sweep; turning storage off refuses new creates and lets existing rows expire on their schedule.
  Logical expiry and confirmed physical deletion are tracked separately; tombstones are kept.
- **C11 Backup/restore wording.** Retention is a DELETION policy, not a durability guarantee: with the v1
  stance (volume outside backups) a volume loss destroys recordings even when the database backup is fine,
  and this must be accepted explicitly by the deployment owner. Restore enters reconciliation mode: rows with
  no blob → `lost`; blobs with no row → quarantine (never deleted); database-only, volume-only and partial
  restores are drilled. Every KEK version still needed is backed up and old keys are kept until no
  dependency remains. **Rotation is a REWRITE, not a re-wrap (see §7, X4):** a frame's AAD binds the header hash, which
  contains the wrapped DEK and key id, so re-wrapping the DEK in a header breaks authentication of every frame.

## 3. Stages (control plane first — old agents never call the new API, new agents must find it live)

- **R1 control plane:** migration (tables, policy, capability preset), signed-request verifier + golden
  vectors, storage writer/reader with AEAD, upload API, finish verification, WebM muxer, retention +
  orphan sweeper, policy API, list/stream/download API with audit. Fake + pg.
- **R2 agent:** signer (golden vectors shared with R1), uploader in the service with sidecar queue state,
  streaming hash (no whole-file read), TTL suspension while pending, rate cap, no upload during a live
  session, local delete on `complete`, text fixes.
- **R3 console:** tenant recording policy settings, recordings list (session history + a Recordings area),
  player with integrity/truncation display, help text.
- **R4 deployment:** volume, env var, Caddy, docs/22/20 rewrites, restore-drill step.

## 4. Tests

Golden vectors (Rust↔Go) for the preimage; signature/time-window/wrong-device/wrong-tenant refusals;
chunk idempotency and resume after a simulated restart; byte-cap and quota refusals; digest mismatch →
not complete; `verified_with_audit` vs `agent_attested`; AEAD round trip, tamper detection, range reads
across frame boundaries; muxer against golden IVF fixtures (and `ffprobe` in the Linux CI VM); retention
expiry + orphan pass by name (a non-UUID dir is never deleted); capability and group-scope gating
(asymmetric); every playback/download audited; e2e: agent→server upload against the real control plane,
console plays it. VM acceptance: a real recording uploads after the session ends and plays in the console.

## 5. R1a as built (control plane: upload path, storage, sweeper) — the contract R2 mirrors

Status: shipped and deployed (migration `0066`). R1b (WebM muxer, policy API, list/stream/download + playback
audit, section 6) builds on the hook point in `control-plane/http_recording_upload.go` (`OnEvidenceComplete`,
called once a recording reaches `evidence_complete`). Code map:

| Spec item | Where |
|---|---|
| C1 signed request, golden + negative vectors | `recording_sig.go`, `recording_sig_test.go`, `testdata/recording_upload_v1_vectors.json` (the Rust agent loads the SAME file) |
| C5 envelope + D4 key wrapping | `recording_envelope.go` (`RecordingKeyring`, `CreateEnvelope`, `ResumeEnvelope`, `OpenEnvelope`) |
| C6 storage over `os.Root`, quarantine | `recording_storage.go` (+ `_unix/_windows/_other` for free space / device ids) |
| C2 state machine, C3 reservation, C10 anchor | `recording_store.go` (rules + fake), `pgstore_recording.go`, `migrations/0066_central_recording.sql` |
| C3 pipeline, deadlines, admission | `http_recording_upload.go`, `recording_admission.go` |
| C4 provenance | `recording_provenance.go` |
| C6/C10 sweeper, startup reconciliation | `recording_sweeper.go` (rides `RunReaperSweep`; `StartRecordingServices` at boot) |
| D6 capability | `rbac.go` `CapViewRecordings` (Owner/Admin/Auditor; not API-token grantable) + the `0066` preset UPDATE |

### 5.1 Wire contract (for the agent)

Routes are ROOT routes (no cookie, no CSRF). Behind Caddy they are `/cp/agent/recordings…`; the proxy strips
`/cp`, and **the signed canonical path is the stripped one** (`/agent/recordings…`).

| Op | Request | Success |
|---|---|---|
| create | `POST /agent/recordings` body `{"recording_id","session_id","generation","segments":[{"index":0,"length":N},…]}` | 201 (new) / 200 (identical replay) `{"recording_id","generation","state","chunk_size":1048576,"segments":[{"index","length","committed_offset"}]}` |
| put | `PUT /agent/recordings/{id}/segments/{n}`, raw body = ONE chunk | 200 `{"committed_offset","resent"}` |
| head | `HEAD /agent/recordings/{id}/segments/{n}` | 200 with `X-Rmt-Committed-Offset`, `X-Rmt-Segment-Length`, `X-Rmt-State` |
| finish | `POST /agent/recordings/{id}/finish` body `{"recording_id","generation","digests":[hex sha256 per segment],"truncated":null or "reason","dropped_frames":N,"frames"?:N,"payload_bytes"?:N}` | 200 `{"recording_id","generation","state":"evidence_complete","digests":[…],"provenance"}` — **this binds recording id, generation and the digest list (C9)** |

Signed headers (every one required exactly once on every op, mirrored in the preimage; the operation and the
canonical path are derived by the SERVER from method + route): `X-Rmt-Device`, `X-Rmt-Tenant`, `X-Rmt-Key-Fp`
(sha256 of the 32 raw pubkey bytes, lower-case hex), `X-Rmt-Recording` (canonical lower-case uuid),
`X-Rmt-Generation` (≥ 1, fixed per recording), `X-Rmt-Segment` (0 for create/finish), `X-Rmt-Offset` (0 except
put), `X-Rmt-Body-Sha256`, `X-Rmt-Timestamp` (unix ms, ±5 min), `X-Rmt-Signature` (Ed25519, 128 hex). The exact
body length is the `Content-Length` (chunked bodies get 411). Numbers are plain decimal, no sign/leading zeros.
No query string; any duplicate header or non-canonical path is 400. The **audience** is the control plane's
public origin, `CP_PUBLIC_ORIGIN`, canonicalised by `NormalizeRecordingAudience` (lower-case scheme+host, no
default port, no path; https only except loopback) — the agent applies the same rules to the control-plane URL
it enrolled against.

Chunk geometry is determined by the declared length: every chunk is exactly 1 MiB except the last of a segment
(the remainder); the offset of chunk *k* is *k* MiB. A PUT is accepted at the committed offset, or as an exact
re-send of a committed chunk (same bytes → 200 `resent:true`, nothing changes); a gap or a misaligned offset is
409 `bad_offset` with `committed_offset`; different bytes at a committed offset are 409 `chunk_conflict`.

Status codes: create — 403 `storage_off` (terminal for this recording; re-evaluated per create), 413 `too_large`
(per-recording cap, terminal), 507 `tenant_quota` / `server_full` (retry later; `Retry-After`), 410 `gone`
(tombstone, terminal), 409 `conflict` / `already_complete`, 404 `session_unknown`, 403
`session_not_on_this_machine`. Any op — 401 (identity, signature, window; deliberately uniform), 403
`machine_not_active` / `forbidden` (another device's recording), 404, 409 `generation_mismatch`, 410, 408 (stalled
or too-slow body), 429/503 (back off and retry with the exponential schedule C9 gives). Finish — 409 `incomplete`
(lists the segments still owed), 422 `digest_mismatch` (the named segments were reset to offset 0 and must be
re-sent; the third failure refuses the recording), 409 `audit_conflict` (a signed `recording_stopped` event
contradicts the upload: refused, terminal), 503 `audit_unavailable` (retry).

### 5.2 Storage and state

`<root>/<tenant>/<recording>/<NNNN>.ivf.enc` (evidence) and `….webm.enc` (playback, R1b); in-flight bytes in
`<root>/.incoming/<upload>/<NNNN>.ivf.enc`; apparent orphans in `.quarantine/<unix>-<…>/` with `MANIFEST.json`.
Every file is an envelope (C5); there is no plaintext on disk. Env: `RECORDING_MASTER_KEY` (hex 32 B; unset = the
feature is off), `RECORDING_MASTER_KEY_ID` (default 1), `RECORDING_MASTER_KEY_PREVIOUS` (`id:hex,…`),
`RECORDING_DIR` (default `/var/lib/deskrally/recordings`), `CP_PUBLIC_ORIGIN`, `RECORDING_RECONCILE_MODE`
(disables the orphan pass and quarantine purge while a restore is reconciled).

States: `uploading → evidence_complete → (playback_ready | playback_failed) → expired → deleted`, plus terminal
`abandoned` / `refused`. The application role has no DELETE (tombstones are kept; the migration REVOKEs it
explicitly because 0005's default privileges would otherwise grant it) and triggers forbid leaving a terminal
state, rewriting create-time metadata, or extending `expires_at`. Quota is the sum of `reserved_bytes` over rows
not yet `deleted`/`abandoned`/`refused`, taken under one advisory lock together with the disk floor.

### 5.3 Interpretations and limits (read before relying on them)

- **Chunk is buffered in memory** (≤ 1 MiB, bounded by the admission limits) while its sha256/length are checked
  against the signed values; it is then written, already encrypted, straight into the in-flight envelope at its
  deterministic position (no per-request temp file) and fsynced inside the segment row lock before the offset moves.
- **Tenant quota exhaustion is 507** (retry later, a retention sweep frees it), not 413; 413 is reserved for the
  per-recording cap. The disk floor subtracts only the not-yet-written part of live reservations from free space.
- **Orphan handling**: the pass never deletes; it quarantines. The ONLY deletion of an orphan is the purge of an
  entry this code created, with a manifest, after `QuarantineGrace` (14 days) — disabled in reconciliation mode.
  The pass holds entirely when the database read failed, when most directories look orphaned, or beyond 50 moves.
- **Admission** (C3): global / per-tenant / per-device concurrency with a bounded wait queue (default 8 / 4 / 2,
  queue 32, 3 s wait → 503 `busy`), a per-device request rate (default 20/s, spent only AFTER the signature has
  verified, so naming a victim's device id cannot use up its budget), and a per-source-address budget of FAILED
  authentications (default 5/s, burst 50) that is checked before any database work and charged only by failures —
  successful traffic never spends it, so a whole fleet arriving from one proxy address does not throttle itself.
  Behind a proxy that is not trusted for `X-Forwarded-For` that address is shared by everyone; set
  `CP_TRUST_PROXY_IP` / `CP_TRUSTED_PROXIES` as for the login throttle.
- **Health**: `Server.RecordingHealth()` (deletion lag, free bytes vs floor, last sweep) and `ALERT` log lines are
  the signal; it is NOT wired into `/readyz` (a full recordings disk must not pull the whole control plane out of
  rotation). R4 should alert on the log lines / scrape the struct.
- **Provenance** also compares `frames` / `payload_bytes` when the finish supplies them. A stop event "claims" the
  recording when it shares any digest with the upload; claim + any disagreement = conflict. Events that are
  unsigned, signed by another key, for another machine, or whose fields no longer hash to the signed hash are
  ignored (they can neither match nor block).
- **Not in R1a** (`lost` was built later, in R4: section 10.3): the policy PUT/GET routes (the store, the strict decoder
  `DecodeRecordingPolicyPut` and the migration are ready), the muxer, list/stream/download, playback audit, the KEK
  rotation command. Caddy timeouts and the volume are R4.

## 6. R1b as built (control plane: WebM playback, policy API, console routes)

Status: shipped and deployed (migration `0067`). R1b closes the control-plane half of
D5/D6/D7 and the §2a C7/C8 contracts.

| Spec item | Where |
|---|---|
| C7 muxer: server-owned bounds, checked arithmetic, exact consumption, two-pass design | `recording_webm.go` (`ScanIVF`, `PlanWebM`, `WebMPlan.Write`); tests `recording_webm_test.go`, fuzz `recording_webm_fuzz_test.go`, golden `testdata/recording_golden_v1.*` |
| C7 async worker queue, cancellation, time budget; evidence vs playback status | `recording_playback.go` (`StartRecordingPlayback`, `EnqueuePlayback`, `MuxRecording`); states `playback_ready` / `playback_failed` + `playback_error`, migration `0067` |
| Playback metadata + list | `recording_store.go` (`RecordPlayback`, `ListRecordings`), `pgstore_recording.go`, `migrations/0067_recording_playback.sql` |
| D5 policy API (GET/PUT, audited, fail-closed) | `http_recording_policy.go` |
| D6 `CapViewRecordings` wiring; never token-grantable | `rbac.go` (R1a), `Principal.APIToken` + `apitoken_auth.go`, `recording_rbac_test.go`, `recording_console_test.go` |
| C8 list / detail / playlist / segment stream (Range) / evidence download | `http_recording_playback.go` |

### 6.1 Routes (protected chain: cookie session, CSRF, tenant-pinned RLS)

| Route | Gate | Notes |
|---|---|---|
| `GET /tenant/recording-policy` | `manage_tenant` or `view_recordings` | `{retention_days, max_recording_bytes, quota_bytes, enabled, storage_available}` |
| `PUT /tenant/recording-policy` | `manage_tenant` (Owner; the Admin preset does not hold it) | every field required and named exactly, unknown / null / out-of-range = 400; **audit row first**, then the change; 500 and no change when the audit write fails; audit action `tenant.recording_policy.set` with old and new values; if the store write then fails, a best-effort compensating `tenant.recording_policy.set_failed` row (same old/new, fixed reason, no error text) says the change did NOT happen (the viewer's audit-category map in `web/viewer/src/lib/audit_notifications.ts` does not list either recording action yet) |
| `GET /recordings?session_id=&machine_id=&limit=&cursor=` | `view_recordings`, group-scoped | completed recordings (`evidence_complete` .. `deleted`), newest first by `(evidence_complete_at, id)`; `next_cursor` names a position in that log, so for a scoped viewer an empty page with a cursor means "nothing of yours in that stretch, keep going" |
| `GET /recordings/{id}` | same | state, provenance code + label + the no-independent-verification note, truncation / dropped frames, per-segment digests and playback metadata, `playback_error` (closed code) |
| `GET /recordings/{id}/playlist` | same | audited "playback started"; 409 `playback_pending` / `playback_failed` (+`reason`), 410 `expired` / `deleted`; items carry relative `segments/{n}/stream` URLs, `start_ms`, `duration_ms`, size |
| `GET /recordings/{id}/segments/{n}/stream` | same | `video/webm`; a single `Range` (206; 416 with `Content-Range: bytes */len`); multi-range / malformed / `If-Range` is served whole; no `ETag` / `Last-Modified` is ever sent, so no conditional can become a 304; audited "playback started" |
| `GET /recordings/{id}/download` | same | ZIP (stored, streamed): `manifest.json` (ids, provenance, digests, truncation, times; it stands in for the agent's JSON sidecar, which the server does not keep) + `segment-NNNN.ivf` evidence; **every** download audited |

The routes are mounted only when central recording is fully wired **and** a management audit store and machine
store exist: content is never served on a deployment that cannot audit or scope it. They are not in the OpenAPI
document and no `/api/v1` alias exists (docs/59 §7).

### 6.2 C8, as implemented

Every route, every request: (1) `Cache-Control: private, no-store` and `nosniff` before anything is decided; (2) not an
API token (`Principal.APIToken`, set by `APITokenAuthenticator`) and holds `view_recordings` (the token check is on the
*flag*, so widening the grantable set cannot open these routes; test: a token that holds the capability is still
refused); (3) the recording exists in this tenant and is a completed one; (4) **group scope on the machine's CURRENT
group** (`AllowsInGroup`): a machine that no longer resolves is visible only to a tenant-wide holder, a machine-store
failure is a 500 (never "allowed", never an empty list), and out-of-scope / unknown / other-tenant are all 404; (5) only
then the state, `Range` and conditional headers; (6) the audit row is persisted before the first byte. "Playback
started" is one row per recording per viewer per 10 minutes across playlist and stream (an in-process cache filled only
from rows that exist, backed by a lookup in the audit store so another replica or a restart is honoured); downloads are
never deduplicated; an audit store that cannot be read or written is a 503 with no content. A download or stream that
fails after the headers went out aborts the connection (`http.ErrAbortHandler`); to make that work `recoverMiddleware`
now lets that one panic through instead of appending a JSON 500 to a half-sent body.

### 6.3 The muxer (C7)

Two passes over the authenticated plaintext, one decrypted frame in memory at a time. **Scan** validates and builds a
24-byte-per-frame index; **plan** computes every element size and position and the exact output length (the envelope
header needs the length up front) and enforces `output <= 1.2 x input + 4 KiB` *before* any output exists; **write**
re-reads the same bytes, re-checks each frame header against the index, and the output length must equal the plan.

* Bounds (`DefaultMuxLimits`): 500k frames per segment, 4 MiB per frame, 8192 x 8192, input <= 1 GiB, segments <= 64
  (the create API), timestamps non-decreasing, window <= 48 h and, when the session has ended, <= session length +
  15 min; segment *k* may not start before segment *k-1* ended. Input is consumed exactly (trailing bytes, a partial
  frame, a source longer or shorter than declared are all errors). Time conversion uses a 128-bit intermediate.
* Accepted input is VP8 only; the first frame must be a key frame; every key frame needs the start code and the file
  header's dimensions; frames under 3 bytes are refused; a non-zero header frame count must equal the real count.
* Output: EBML header, Segment (8-byte size), SeekHead, Info (Duration = last frame + one typical interval), Tracks,
  **Cues before clusters** (one per cluster that starts on a key frame), Clusters (a new cluster at the next key frame
  after 2 s, forced at 30 s of gap or 8 MiB). All fixed-width, so sizes never depend on values. Each segment starts at 0;
  the playlist's `start_ms` places it on the recording's timeline (idle gaps keep their wall-clock length).
* Failure reasons are a **closed set** (`invalid_ivf`, `limit_exceeded`, `time_budget`, `io_error`,
  `inconsistent_ivf`, `internal`), enforced by a CHECK in `0067`: nothing derived from the input is ever stored or shown.
* Pass 2 hashes what it consumed and refuses to publish unless it equals the digest finish verified.
* No `ffprobe` exists on the build box, so the tests check the output with an independent EBML walker (every size,
  every SeekHead / Cues position, every frame byte); running `ffprobe` over `testdata/recording_golden_v1.ivf`'s output in
  the Linux CI VM is still worth doing once (docs/63 §4).

### 6.4 The worker queue

`finish -> evidence_complete -> EnqueuePlayback -> bounded queue (64) -> 2 workers -> MuxRecording`. Enqueue never
blocks and never fails the upload; a full queue, a restart mid-job or a replica that never enqueued is recovered by the
5-minute sweep, which re-offers every `evidence_complete` row. A job has a 10-minute budget (`time_budget` ->
`playback_failed`); shutdown cancels running jobs and they record **nothing** (the row stays `evidence_complete` and the
next process retries). A `playback_failed` recording is **not** re-offered by the sweep (a pathological input would
starve the workers every tick); `MuxRecording` itself accepts a retry from `playback_failed`, but R1b has no HTTP route
for it. Each attempt writes under its own fresh `.incoming/<uuid>` directory and publishes with an atomic rename, so two
replicas muxing the same recording cannot corrupt each other; the store admits one outcome (`ready -> ready` is
refused). A worker panic is recovered and parks the row as `playback_failed("internal")`.

### 6.5 Interpretations and limits

* The playback copy is encrypted under the recording's existing DEK with a fresh random nonce prefix per file
  (generation = the recording's generation).
* A mux that loses the race with expiry can publish a WebM into a directory whose row is already `expired` / `deleted`;
  the next retention pass removes it (`expired`) or the orphan pass quarantines it (`deleted`).
* `Admin` cannot change the policy (the preset has no `manage_tenant`); Auditors and Admins can read it.
* Still not built: the KEK rotation command, an operator "retry playback" route.
* For R4: alert on the `recording playback:` / `recording console:` log lines. A job holds at most one decrypted 64 KiB
  frame plus a ~12 MB frame index, so `Workers x ~15 MB` is the muxer's memory bound.

## 7. Implementation review — what changed and what it means

Parts A-D and the cross-part checks X1-X7 of a second independent review. Tests are in `http_recording_review2_test.go`,
`recording_review2_store_test.go`, `recording_review2_console_test.go`, `recording_storage_race_test.go`,
`recording_webm_eof_test.go`, `recording_console_deadline_test.go`.

* **Per-recording lock (A1, X5).** `RecordingStore.LockRecording(ctx, tenant, id)`: a pg SESSION advisory lock
  (`pg_advisory_lock(hashtextextended('rmt-recording:<tenant>/<id>', 0))`) held on a dedicated pool connection, or
  a per-recording mutex in the fake. It serialises, per recording and across processes: the whole finish
  (re-read of the row, digest passes, provenance, promote, `CompleteEvidence`, and the rollback with its state
  check), the sweeper's abandon / expire / delete, and the playback publish (`muxPublish`: state re-check +
  rename). The chunk path takes only row locks (never this lock), so there is no cycle. A rollback can no longer
  move acknowledged evidence back to incoming, and a worker cannot publish into a directory retention is removing.
* **Bounded finish (A2).** The lock wait, the digest passes (cancellable between frames) and the provenance scan
  share one `FinishWork` budget (503 `busy` / `audit_unavailable` when spent). The audit traversal is capped at
  200 pages of 10k events (`recProvenanceMaxPages`); beyond that is an error, never a weaker label. Concurrent
  finishes of one recording coalesce: the later ones wait, re-read the row and answer as an idempotent replay.
* **Replay (A3).** A replayed finish must match digests, truncation, dropped frames, `frames` AND
  `payload_bytes` (absent matches only absent), on both the normal and the concurrent-completion path.
* **Upload lifetime (X7).** Enforced on every request (410 `upload_expired`), anchored on the row's creation;
  an idempotent create replay cannot revive a dead upload.
* **Reservation (B1).** The playback copy is reserved at the muxer's HARD maximum (1.2 x input + 4 KiB, the same
  constants the plan enforces) plus envelope overhead, for every segment; the playback file is renamed into
  place, never copied, so evidence + one maximum playback file is the peak. Rows created before this change
  keep their old (1.1x) reservation.
* **Durable retention (B2).** `ApplyRetention` persists `expires_at = LEAST(stored, evidence_complete_at +
  current positive retention)` under the row lock on every sweep, before classification. Lengthening the policy
  or switching storage off later never restores the longer schedule. (The 0066 trigger already allows only
  earlier moves.)
* **Playback validation (B3).** `validatePlaybackSegments` enforces the 8192 dimension ceiling migration 0067
  has, so fake and pg refuse the same inputs with the same error.
* **Pinned storage (C1).** Every operation is relative to a directory handle pinned component by component
  (Lstat, `OpenRoot`, `os.SameFile`, device check); `os.Root` follows in-root symlinks, so the identity check is
  what refuses a swapped component. Files are opened and unlinked by name inside the pinned directory;
  deletion removes the directory entry only if the parent still names the pinned directory. On Linux the
  two-directory moves (promote, unpromote, quarantine) are `renameat(2)` on the pinned descriptors; elsewhere
  (Windows development hosts) `os.Root` has no two-handle rename, so the move goes through the volume root and is
  VERIFIED afterwards: a substitution inside that single call is detected and reported, not prevented.
  Reparse points / junctions are refused (not a plain directory).
* **Directory fsync (C2).** Required and propagated: a failed parent sync keeps a deletion pending (also when
  the directory is already gone, so the retry syncs), quarantine syncs the manifest, the entry, `.quarantine/`
  and the old parent and reports a failure. **Windows cannot fsync a directory handle: there, and only
  there, it is an explicit no-op** (NTFS journals metadata); production (Linux) propagates every error.
* **Muxer EOF (D1).** `requireEOF`: exactly zero bytes and `io.EOF` in both passes; an authentication failure
  of the next envelope frame (e.g. at an exact frame boundary) is propagated as an I/O error.
* **Deadlines (D2).** `newDeadlineWriter` sets and checks the write deadline before the first header of a
  stream/download (500 `deadlines_unavailable` otherwise); a failed refresh stops the write.
* **X1** `ReadRange` returns at most 8 MiB per call (the routes already read 256 KiB / 1 MiB steps).
  **X2** list, detail, playlist, stream and download treat a completed row past `expires_at` as `expired`
  (410 on content) before the sweeper flips it; the muxer skips such rows.
* **X3 (not a defect)** `OpenEnvelope(..., allowPartial=false)` requires the exact file size the authenticated
  header implies, the final-frame flag is in each frame's AAD, `WriteTo`/`Sequential` read every frame including
  the final one (tests: truncation, trailing byte, frame-aligned prefix in `TestEnvelopeTamperDetection`).
  **X6 (not a defect)** `recCreate` refuses a session whose machine is not the signing machine
  (403 `session_not_on_this_machine`, test in `TestRecordingUploadCreateRules`).
* **X4 KEK rotation = REWRITE.** No rotation command exists. Because every frame's AAD binds the header hash
  (wrapped DEK and key id are in the header), re-wrapping a DEK in place cannot work. A rotation must write
  each file anew under a fresh DEK, generation and nonce prefix (decrypt, re-encrypt, promote, then update the
  row's key). Until that exists, `RECORDING_MASTER_KEY_PREVIOUS` is the READ path for every older file and every
  KEK version that wrapped a stored file must be kept and backed up.


### 7.1 Re-review of those fixes

* **Lock pool.** `PgRecordingStore.LockRecording` takes its session advisory lock on a SEPARATE bounded pool
  (`LockPoolMax`, default 16, built from the query pool's own configuration), never on the query pool: holders
  and waiters cannot starve the operations a holder needs. A waiter (or a caller that finds the lock pool full)
  gives up after `LockWait` (default 15 s) with `ErrRecordingLockBusy`, which the finish answers as 503 `busy`.
  Tests: a 1-connection query pool; lock-pool saturation by same-recording waiters.
* **Post-lock load.** The authoritative read after the lock, and every later finish DB call, runs under the
  finish budget context (`recLoadOwnedCtx`); the rollback's state check is bounded separately (10 s).
* **Idempotent syncs.** `Promote` / `Unpromote` success branches for an already-moved file redo the required
  directory syncs (destination, its chain, the source side where it exists, `.incoming`) before acknowledging; a
  directory created by an attempt whose parent sync failed is remembered in-process and re-synced on the next pin
  (restart-safe through the syncs `Promote` now always performs on the tenant directory and the volume root).

## 8. R3 as built (console: policy settings, Recordings area, player)

Status: shipped and deployed (web/viewer only; no server change).

* **Policy** (`RecordingPolicySection`, inside the Security panel): retention Off / 30 / 90 / other (1-365), largest
  recording (MiB, at most 1024), tenant quota (GiB). Off is worded "recordings stay only on the guest machine".
  Saving from Off to a positive retention asks first (inline confirmation, nothing sent until confirmed). The PUT always
  carries all three fields (`ConsoleApiClient.setRecordingPolicy` spells them out; `parsePolicyForm` keeps an untouched
  non-round stored size exact). A positive retention with quota 0 or quota below the largest recording is refused locally.
  The section is hidden on 403/404 from the GET; a PUT 403 reads "Only an Owner can change the recording policy".
* **Recordings area** (`RecordingsPanel`): offered only when `GET /recordings?limit=1` succeeds. The console holds no
  capability list (`/me` returns none; `GET /roles` needs manage_roles), so the probe is the gate; every request is
  authorized again by the server. Rows: status (Uploading / Evidence complete / Playback ready / Playback failed /
  Expired / Lost; `deleted` also reads Expired), machine, technician, session start/end, size, the C4 provenance label
  (worded from the machine code, tooltip = neither is independent capture verification), truncation and dropped-frame flags.
* **Player** (`RecordingPlayer`): detail first, then the playlist only for a ready recording (the playlist fetch is the
  audited "playback started"; one fetch per open, also under StrictMode). `<video>` plays `segments/N/stream`
  (only that exact relative form is accepted) and advances on `ended`. A video error probes the stream with a 1-byte
  Range request to name the real status (403/410/503). The evidence ZIP is a same-origin link (server streams and audits).
  409 pending/failed, 410 expired, 403, 503 each have their own message.
* Help text, the Record button tooltip and two control.ts comments no longer say recordings are guest-only.

API gaps found (none blocking): the list names only ids, so machine, technician and session start/end are joined
client-side from `GET /machines`, `/sessions`, `/users` (best effort; ids shown when a join fails), and there is no
recording start/end of its own (the session's are shown; `evidence_complete_at` is not displayed). The session list
exposes no recording id, so session-history rows do NOT link to recordings yet (the list does accept `session_id`,
so a later "has recording" lookup is possible). The evidence download is a plain link, so a refusal (410/503) during a
download shows the browser's failed-download message, not ours; the link is only offered while the evidence exists.
The viewer's audit-category map still lacks `tenant.recording_policy.*` and the recording playback/download actions.

### 8.1 Follow-up: server-side context and the session-history link

* `GET /recordings` rows and `GET /recordings/{id}` now carry, when known: `machine_name`, `machine_alias`,
  `technician_id`, `technician_name` (display name, else email), `session_started_at`, `session_ended_at`. They are
  joined in the handler (`recJoin`, from the session store and the user store) AFTER rule 4, so they are fields of a
  session the caller was already authorized to see this recording for; a failed or empty lookup omits them. The
  schema stores no capture time (the agent's timestamps are not kept), so the times are the SESSION's, named so. The
  console dropped its client-side joins and falls back to ids only when a field is absent.
* `GET /sessions` rows carry `recording_id` (the session's newest completed recording, `RecordingStore.RecordingIDsBySession`,
  fake and pg) only when the caller holds `view_recordings` over the machine's CURRENT group, is not an API token, and
  recording is fully wired. Otherwise the field is ABSENT (never null/false), so existence does not leak. A lookup failure
  omits it and never fails the session list. The console shows a "Recording" button on those rows (only while the
  Recordings area is itself offered); it opens the recording in the player.
* Not changed: GET /me (the capability probe on `/recordings` remains the console's gate).

## 9. R2 as built (agent: signer, uploader, queue)

Status: shipped and deployed (crates/agent-windows only; no server change). The agent half of C1/C2/C9 and the
§5.1 wire contract.

| Spec item | Where |
|---|---|
| C1 signer (preimage, signature, canonical path, audience normaliser, ±5 min window helper) | `recording_upload_sig.rs`; tests load `control-plane/testdata/recording_upload_v1_vectors.json` (positive: preimage AND signature byte-identical; negative: every field; window cases) |
| §5.1 HTTP client (ten `X-Rmt-*` headers, exact Content-Length, no redirects, stripped signed path, bare-origin audience) | `recording_upload_http.rs` (`HttpUploadApi`), `tests/recording_upload_wire.rs` |
| C9 queue: state per recording, bounds, backoff, local-TTL hold, binding-ack deletion, finish-or-abandon | `recording_upload.rs` (`Uploader`, `UploadState`, `StateStore`, `classify`, `is_held`) |
| Service wiring | `service.rs` starts `UploadWorker` (idle unless enrolled; re-reads `config.json` every 30 s pass) |
| Local sweeps honour the hold | `recording::sweep_expired` (flat dir) and `recording_broker::storage_budget` (CLI leaf dirs) |
| Rust↔Go interop against the REAL handler | `control-plane/recording_rust_agent_test.go` (build tag `rustinterop`) |

How it behaves. After a recording is finalised (sidecar present) the service worker queues it: one `<id>.json` under
`C:\rmt-agent\recording-uploads\` (beside, never inside, the recording directories: the CLI broker's budget pass refuses
unknown files in its leaves). The recording id is deterministic (`sha256(device, dir, stem)` shaped as a v5 uuid), so a lost
state file re-queues the SAME id and the server's create replay is idempotent. Every segment is stream-hashed (64 KiB steps)
against the sidecar digest before any byte is sent; a file that changed is refused. `create` is the first call and the
resume handshake (it returns committed offsets); after a restart each segment is also HEADed. Chunks are 1 MiB, paced to
250 000 B/s (2 Mbit/s). The finish carries digests, `truncated`, `dropped_frames` AND the summed `frames` / `payload_bytes`
(exactly what `recording_stopped` seals, so a normal stop matches the audit event). Local files are deleted ONLY when the
finish answer binds recording id, generation, status `evidence_complete` and the exact ordered digest list.

Storage on/off is learned per recording from `create` (403 `storage_off` = "not stored", this recording only; the next one
asks again) — the wire contract has no other signal.

Fleet uninstall hand-off (docs/65 D-C9): `recording_upload_http::finish_or_abandon_pending(budget)` completes what it can
(ignoring the live-session gate, backoff and the rate cap) and EXPLICITLY abandons the rest (`uninstall`,
`uninstall_budget`, or `uninstall_unwired` when the machine cannot even be wired), returning a `DrainReport`; afterwards
nothing is pending. `abandon_pending_for_reenrollment()` is the immediate form for a re-enrollment path; the uploader also
abandons any entry queued under another key/tenant/device/audience by itself (`identity_changed`).

### 9.1 Limits and open points

* **Live-session gate.** The service cannot see the helper's session list. `FsSessionProbe` defers uploads while (a) a
  recording is in progress (an `.ivf` without its sidecar written in the last 5 min) or (b) a helper's live-session marker
  under `C:\rmt-agent\` was refreshed in the last 2 min. Each helper stamps its own `session-live.<pid>` marker while any of
  its session tasks is alive (`session_live.rs`, refreshed every 30 s and removed when the last one ends).
* The CLI broker hold (`storage_budget`) has no unit test (it needs the broker's trusted-directory ACL checks); the flat
  sweep hold is covered.
* `rmt-agent-windows` clippy is not clean crate-wide on main (119 pre-existing warnings); the new files add none.
* Uploads are not wired into the helper-less (`--recording-service` only) paths specially: both layouts are scanned.
* The interop test is behind `-tags rustinterop` (needs cargo); the no-skip gate would count a plain `t.Skip` as a
  failure, so it is compiled out rather than skipped. verify-all can add `go test -tags rustinterop -run TestRustAgent`.

## 10. R4 as prepared (repo side)

Status: shipped and deployed (migrations `0077` for `lost`, section 10.3). **Principle: opt-in that ships off** (the docs/66
`CP_EDGE_SECRET` pattern): a routine deploy of this change enables nothing and adds nothing that can stop the control plane
starting. Storage turns on only when `RECORDING_MASTER_KEY` is non-empty; every new `.env` value defaults to empty.

| What | Where | Notes |
|---|---|---|
| Compose: `RECORDING_MASTER_KEY`, `_ID`, `_PREVIOUS`, `RECORDING_RECONCILE_MODE`, `RECORDING_RECONCILE_ACCEPT_MISSING`, `RECORDING_DISK_FLOOR_MIB`, `CP_PUBLIC_ORIGIN` forwarded with EMPTY defaults; fixed `RECORDING_DIR=/var/lib/deskrally/recordings` (the code's own default); named volume `recordings` mounted there | `deploy/docker-compose.prod.yml`; empty lines in `deploy/.env.example` | The base file is untouched (it is the dev bring-up). `CP_PUBLIC_ORIGIN` had to be forwarded too: it is required once the key is set and nothing forwarded it. No `:?` anywhere, so an existing `.env` keeps working. Mounting the empty volume while storage is off is harmless: nothing opens it. The comments carry the `down -v` destroys-recordings warning and the "outside the backup contract in v1, pending the deployment owner's C11 acceptance" warning. |
| Volume ownership | `control-plane/Dockerfile` creates `/var/lib/deskrally/recordings` (`app:app`, 0700) before `USER app` | The image's runtime user is `app`, uid 10001 (verified in the Dockerfile). Docker creates a missing mount point as root, which uid 10001 cannot write; an EMPTY named volume copies up the image directory's owner and mode on first use, so owning it in the image is what makes a fresh volume work. A volume first created by an older image stays root-owned: docs/20 15.1 has the check and the one-line chown. |
| Caddy, upload | `deploy/Caddyfile` (and `deploy/native/Caddyfile`): `@recUpload` (`/agent/recordings`, `/agent/recordings/*`, matched after the `/cp` strip) gets `request_body max_size 1088KiB` and a transport with `write_timeout 4m`, `response_header_timeout 12m`, `read_timeout 12m`, `dial_timeout 5s` | The server's per-request ceiling is `RecChunkSize` = 1 MiB (create/finish 16 KiB); 1088 KiB is that plus 64 KiB of headroom. The timeouts outlast the server's own deadlines (chunk 3 min, finish 10 min). |
| Caddy, playback/download | `@recStream` (`/recordings/{id}/segments/{n}/stream`, `/recordings/{id}/download`): `flush_interval -1`, `dial_timeout 5s`, `response_header_timeout 2m`, and deliberately NO read/write timeout; both paths are also excluded from `encode` | Caddy's default is no timeout; the comment keeps a later tidy-up from adding one. The control plane's own 30 s / 60 s per-write deadlines are the slow-peer bound. |
| Every other `/cp` route | unchanged: the old proxy is now the last `handle` inside the same `handle_path` | `#| header_up X-DeskRally-Edge` is repeated in each of the three proxies, so the docs/66 opt-in still marks every `/cp` request. |
| Operator docs | docs/20 section 15 (turn on, verify, policy, turn off, rotation, disk), docs/22 sections 0, 4, 5 (key in the must-back-up set, volume outside the contract, reconciliation as the code really does it) | The old docs/22 lines that told operators to back up the volume with the database, and "agent-local recordings remain on the agent", are replaced. |
| Guards | `control-plane/cmd/controlplane/compose_recording_test.go` (off by default; volume at `RECORDING_DIR` = the code's default; Dockerfile owns the mount point; Caddy cap >= `RecChunkSize`) and `scripts/test-caddy-recording-routes.mjs` (real Caddy, shipped Caddyfile: whole chunk through with `/cp` stripped, 2 MiB refused, 3 s-late headers survive, streaming not buffered or compressed, other routes unchanged, adapted timeouts; `CAP_CONTROL=off` is its negative control) | `compose_env_test.go`'s allowlist no longer exempts the five `RECORDING_*` / `CP_PUBLIC_ORIGIN` variables: they are forwarded now, and the test would fail if they were not. |

### 10.1 What the deployment owner has to do

1. Take the deployment owner's explicit **C11 acceptance** (volume outside backups, retention is a deletion policy, key in the
   must-back-up set) BEFORE any tenant sets a retention. Nothing in the repo can substitute for it.
2. Deploy as usual (the tag). The Dockerfile change means the control-plane image is rebuilt; validate the Caddyfile before
   reloading (`caddy validate`, as the banner says) and reload it, because the Caddy handling is live from the deploy even
   with storage off. Confirm `docker volume ls` shows the `recordings` volume and `docker compose config` shows the mount.
3. Back up the generated master key, then follow docs/20 section 15. First production enablement should be one tenant, one
   short-retention recording, played back in the console.
4. Real-box checks the repo's own tests could not make: a fresh named volume really is writable by
   the control plane after copy-up (docs/20 15.1 `ls -ld`), and the `compose config` merge shows exactly one `recordings` mount.
5. Confirm on the real box the statuses docs/20 15.3 states but the repo's tests did not verify: an unauthenticated POST with Content-Length 0 answers 400, an agent treats a 404 on a missing recording route as terminal `not_found`, and removing the key runs no sweep.
6. Alert on the log lines named in 5.3 and 6.5 (`recording sweep: ALERT`, `recording playback:`, `recording console:`); there is no
   metric endpoint.

### 10.2 Limits, said plainly

* **`lost` exists** (migration 0077, section 10.3): a row whose files are missing after a restore is marked by an operator-run
  reconciliation pass (`RECORDING_RECONCILE_MODE=1`), never in normal operation; docs/22 has the exact drill.
* **No rotation command** (7, X4): rotation today means a new current key plus `_PREVIOUS`, with every old key kept.
* The disk floor is configurable (`RECORDING_DISK_FLOOR_MIB`, default 5 GiB, section 10.3); chunk size, admission limits and sweep interval are constants, not environment variables.
* Removing the key stops the sweeper and unmounts the routes; files stay on the volume (docs/20 15.5).
* `scripts/test-caddy-edge.mjs` (the docs/66 matrix) was run on Caddy 2.11.7 against this file and against the unmodified file:
  both fail the same two HTTP/2 cases, so they predate this change (the matrix was last recorded on 2.10.2). Both were
  2.11.7 behaviour changes, not holes; the matrix now accepts either outcome and passes on both versions (docs/66, "Caddy 2.11.7").

### 10.3 Owner conditions on C11, as built

The deployment owner accepted C11 (recordings volume outside the backups) on conditions; the two that needed code are built.

* **Configurable disk floor, default 5 GiB.** `RECORDING_DISK_FLOOR_MIB` (whole MiB, 512 to 1048576; empty or unset = 5120).
  `RecordingFloorFromEnv` (`recording_envelope.go`) refuses anything else at startup (`log.Fatalf`, naming the variable and the bounds, never echoing the value), even
  while storage is off: a mistyped floor never falls back silently to another number, and bytes typed as MiB are caught by
  the upper bound. It was a hard-coded 2 GiB before and nothing read an environment variable for it. The check itself is
  unchanged: fail-closed and made under one lock against free space minus live reservations. The volume shares the root LV with
  Postgres on the reference host, so the floor also protects the database (docs/20 15.1, docs/22 section 4). An `ALERT` line
  is logged on the 5-minute sweep tick while below the floor AND the moment a create is refused for it (507 `server_full`,
  including a volume that could not be measured), the latter at most once a minute so a burst of retrying agents cannot flood
  the log (`alertFloorRefusal`, `http_recording_upload.go`).
* **`lost` (migration 0077) and restore reconciliation.** New state `lost`, entered only from the states that promise the evidence
  copy is on disk (`evidence_complete`, `playback_ready`, `playback_failed`; `uploading` holds only `.incoming`, `expired` is
  already being unlinked, the rest hold nothing), with `lost_from` and `lost_at` columns and the schema's state machine
  enforcing the transitions (`lost_from` and `lost_at` are loss history: only the transition into `lost` may set them, and a restore, an expiry or
  any plain UPDATE can neither clear nor rewrite them) (`lost` to the three live states when files reappear, or to `expired` by retention, never anywhere
  else; the 0066 tombstone, RLS and no-DELETE guarantees are untouched). The pass is `Server.ReconcileRecordingLost`
  (`recording_reconcile.go`), run at startup and on each sweep tick **only** while `RECORDING_RECONCILE_MODE=1`:
  * It marks a row lost when any evidence segment file is absent (presence by name and type, under the per-recording lock, with
    the check repeated inside it), audits it (`recording.lost`, with `lost_from`), and logs one summary line.
  * **HOLD** (marks and restores nothing, logs an `ALERT`, reports why) when the volume root cannot be read; when at least 10 rows are
    checked and more than half are missing; or when the volume has no recording directory at all while rows claim files. It
    mirrors the orphan pass's hold. `RECORDING_RECONCILE_ACCEPT_MISSING=1` is the operator's statement that the right volume is
    mounted and the loss is real and overrides the last two (the count-based holds), never the root checks: the root is also re-read inside the lock before EVERY lost
    decision, and a root that is unreadable, or that showed recording directories when the pass began and shows none now, stops
    the pass at that point (`held mid-pass`, `ALERT`; what was already marked stays) whatever the switch says. "Absent" means
    exactly "does not exist": a row whose files cannot be inspected for any other reason, or whose segment file EXISTS but is
    EMPTY (damage, not a loss), is counted `unreadable` and left alone, and an empty file reappearing does not restore a lost row.
  * **Restore-on-reappear** is allowed, in reconcile mode only: its sole evidence is the files being there, it is cheap, and
    the alternative is a recording lost for ever though its bytes came back with a later volume restore. The row returns to
    `lost_from` (or to `evidence_complete` when it was `playback_ready` and the playback copy did not come back, so the muxer
    rebuilds it) and is audited (`recording.restored`).
  * A `playback_ready` row whose evidence is present but whose WebM is missing becomes `playback_failed` (`io_error`): evidence
    stays downloadable, only the playable copy is gone.
  * **Never served.** List and detail show `lost` (`playable:false`); playlist, stream and download answer `410` with `error:
    "lost"` before storage is touched; no playback job is ever queued for a lost row; the sweeper expires it by retention like
    any row and its unlink is a no-op; its quota reservation is held until then (it may yet be restored).
  * Console: status "Lost" with "The file is missing after a restore", no Play and no Evidence ZIP, and a plain 410 message in the
    player (opened from the Recordings area or the session-history link).
* **Console notice.** "Recordings are not backed up. A disk or server loss deletes them." is shown where a tenant turns storage on
  (the recording policy section, whatever the retention choice), in the Recordings area, and inside the confirmation that
  turning storage on requires.
* Tests: `recording_floor_test.go` (env parsing, the create-refusal ALERT and its rate limit), `recording_lost_store_test.go` +
  `recording_lost_pgstore_test.go` (one suite over the fake and Postgres, plus the schema-level constraints),
  `recording_reconcile_test.go` (mark, serve-refusal, outside-the-mode no-op, each hold, restore, demotion, retention);
  viewer `recordings.test.ts` and `RecordingsNotBackedUpNotice.test.tsx`.
