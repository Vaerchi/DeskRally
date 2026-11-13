# docs/65 — Reinstall and remove an agent without opening a session (design)

docs/01 §6 "Central client update, reinstall, and removal" (P1 `[~]`): auto-update is central, but reinstall
and removal need a live session. Mapped by a read-only survey 2026-10-31.

## 1. What the map established

- Removal exists only in-session: `EndSession{uninstall:true}` → after the session, `perform_self_uninstall`
  (`service.rs`) spawns a detached `cmd.exe` that stops/deletes the service and `rmdir`s the install directory
  AND `CONFIG_DIR` (identity key, recordings). It does not run an MSI uninstall, so the product registration is
  left behind; it deletes the directory of `current_exe()` (a promoted stub in a Downloads folder would delete
  Downloads — docs/23 #3).
- Retire / quarantine only set `machine.status` and end live sessions; they never reach the agent. **The
  device-identity lookup (0055) ignores `machine.status`, so a RETIRED machine still registers and shows
  online** — a defect independent of this feature (F0 below).
- The control plane never pushes to an idle agent. Signaling's `Registered.Features` is the extension hook.
  Agents already pin the control plane's grant-issuer public key (signed grants and leases).
- Auto-update is a pull of a static, signed, per-ring manifest with digest checks, HealthGate and rollback.
- `CapManageMachines` is API-token-grantable and has a 200-id bulk form; `CapDeployAgent` gates nothing and is
  held by Technicians; step-up (`MFAVerifiedAt`) is written but never read.

## 2. Decisions

**F0 — Retired machines stop registering** (ships first, alone): a new migration redefines the identity
function FROM ITS LATEST DEFINITION and refuses `status = 'retired'` (and the new terminal `removed`).
Quarantined machines keep today's semantics (verify and pin with a test: sessions refused, presence visible).
Un-retiring restores registration on the agent's next retry. Tests: retired refused, active control
registers, re-activated registers again.

**F1 — Per-machine signed directives, two kinds: `reinstall` and `uninstall`.** No bulk/id-list route (a
200-id loop would be a fleet wipe in a few calls); fleet waves are out of scope for v1.
- New capability `CapRemoveAgent`, Owner preset only, excluded from `apiTokenGrantableCaps` (pinned by a test,
  like `CapElevateSession`). Group scope applies (`AllowsInGroup` on the machine's group).
- `reinstall`: repair to the CURRENT signed ring release through the existing update chain (digest, HealthGate,
  rollback; same version allowed; no URL ever comes from the directive); keeps identity and config. Single
  `CapRemoveAgent` holder; no step-up.
- `uninstall` gates, ALL required: the machine is already `retired`; the actor's interactive session has a
  TOTP step-up within 10 minutes (`MFAVerifiedAt` gets its first reader; token principals refused); a typed
  confirmation of the machine name; a per-tenant cap (10/hour); a 15-minute cancel window before issuance
  during which any `CapRemoveAgent` holder can cancel; optional tenant policy "require a second approver"
  (different user) — default off so single-owner MSPs are not locked out, recommended on in the UI.
- Audit-FIRST: the audit row and the directive row are written in one transaction before anything is issued;
  issue, delivery, agent ack, completion, cancel and expiry are separate audit events.

**F2 — Signed artifact.** `RMTDIRECTIVEv1` signed by the control plane's grant-issuer key (already pinned by
every agent): device id, tenant id, directive id, kind, issued_at, expires_at (reinstall 24 h; uninstall 1 h
after issuance), nonce. Rust + Go golden vectors incl. negative vectors. The agent refuses every directive
when no issuer key is pinned, on a signature/device/tenant mismatch, when expired, or when the id is already
in its single-use ledger.

**F3 — Delivery.** The control plane notifies signaling (`POST /internal/devices/{id}/directive`, service
token) at issuance; on every authenticated agent registration signaling asks the control plane for pending
directives; it relays only to the authenticated device and only if the agent advertised `directive_v1`.
Signaling is a relay, never an authority (the signature is checked by the agent). Acks flow back the same way
and are recorded centrally (the agent's local chain dies with its config directory).

**F4 — Agent execution.** One removal function used by both the in-session and directive paths: verify the
install location IS the MSI location (refuse attended stubs, promoted download directories, anything else);
run the MSI uninstall (`MsiConfigureProductEx` → absent) so the product registration is removed; then delete
the config directory INCLUDING `identity.key` (a removed device cannot silently return — stated in the
confirm dialog together with "local recordings on the machine are deleted"). On completion the control plane
marks the machine `removed` (terminal; F0 refuses its registration).

## 2a. Review r1 (Codex, "repair") — binding contracts; SUPERSEDE §2 where they differ

- **D-C1 Retired machines get a RESTRICTED channel, not none** (fixes the F0/F3 contradiction). Registration
  of a `retired` machine succeeds in restricted mode: no presence (shown as "retired", never online), no
  session brokering of any kind, only directive retrieval and acknowledgements. `removed` is refused outright.
  Tested: retire while offline → reconnect → uninstall delivered; signaling restart; un-retire restores normal
  registration.
- **D-C2 One authorization path for every removal.** New agents ignore `EndSession{uninstall:true}` unless it
  carries a valid signed uninstall directive for this device; the console's in-session "Uninstall" creates a
  directive request with the same gates. Old agents still honour the bare flag (cannot be fixed server-side;
  documented, and the console stops offering it to them).
- **D-C3 Separate directive key.** Directives are signed by a dedicated `DIRECTIVE_SIGNING_SEED` key, not the
  grant issuer. Agents pin its public key at enrollment (enroll response) or via the MSI property
  `DIRECTIVE_PUBKEY` at install/upgrade, into the ACL-protected config; a compromised grant signer cannot
  replace it; agents without a pinned directive key refuse all directives.
- **D-C4 Atomic issuance.** The pending→issued transition (after the cancel window) runs under the tenant
  issuance lock and rechecks: tenant active, machine still retired and in a group the requester (and approver)
  still cover, both still hold `CapRemoveAgent`, policy unchanged, not cancelled. Step-up freshness is checked
  at REQUEST time and the request is immutable from then on (confirmation and approval bind to its id).
  Cancellation requires the same scoped authorization. One active directive per device; quotas enforced at
  reservation AND issuance; reinstall limited to 3/device/day; retiring/un-retiring or moving a machine with a
  pending removal requires cancelling it first.
- **D-C5 Crash-safe execution.** The agent persists an operation record (directive id, enrollment generation,
  state accepted → executing → failed | reboot_pending | complete) BEFORE side effects and resumes or
  reconciles after a crash; operations are serialized with auto-update. Directives bind the enrollment
  generation (key fingerprint), reject future `issued_at` beyond 2 min skew and lifetimes beyond the maximum.
- **D-C6 Verified completion.** Removal is orchestrated by a helper copied OUTSIDE the uninstall target into a
  SYSTEM-only temp directory: it runs the MSI removal, checks return codes and reboot requirements, deletes the
  validated config directory, and reports the authenticated result before exiting (signed with the still-
  present identity key captured beforehand). States: accepted, executing, failed, reboot_pending, complete. If
  the final report cannot be delivered, the machine stays `removal_unconfirmed` (visible), never silently
  "complete".
- **D-C7 Safe targets.** Before deleting anything: verify the MSI product code and per-machine install
  context, canonical paths without reparse points, SYSTEM/Administrators ownership and ACLs of every target;
  no shell-generated deletion commands; revalidate immediately before each delete. Tests: junction, path swap,
  unexpected product code, partial MSI failure.
- **D-C8 Acknowledgements and endpoints.** Agent acks are signed by the device key and bound to tenant,
  device, enrollment generation, directive id and a valid state transition; signaling's internal endpoints
  derive routing from the stored directive row, never from caller-supplied ids. Every human endpoint
  (request, approve, cancel, list) applies tenant + current group authorization.
- **D-C9 Removal tombstone.** On complete the machine becomes `removed` (terminal): its device id and key
  fingerprint are tombstoned and refused by enrollment as well as registration; a re-install enrolls as a
  NEW machine only through a fresh enrollment token, linked to the old record for history. Central evidence
  (audit, directive records) is kept. Local recordings: the confirm dialog states they are deleted unless
  central storage (docs/63) is on and their uploads are complete; the agent finishes or explicitly abandons
  pending uploads before removal.

## 2b. Final-ack route (operator decision 2026-11-01)

**Problem.** After the MSI uninstall a SYSTEM helper sends the final signed `complete` ack (RMTDIRACKv1, device key) and only then deletes `identity.key`. If the control plane applied `complete` (machine -> `removed`, the D-C9 tombstone) but the response was lost, the helper could never confirm: every channel goes through device registration, and a removed device is (correctly) refused there. Removal confirmation must be knowable.

**Route.** `POST /agent/directives/{id}/final-ack` on the control plane's PUBLIC mux (beside `/enroll/redeem`, outside the auth -> tenant chain; mounted only when the internal directive routes are). Body (strict JSON, 16 KiB cap, unknown fields rejected, so a `device_id` is a 400): `{"from","to","ts_ms","detail","sig"}`. The caller supplies NO device or tenant id.

- **Authorization is the signature alone, bound to the stored row.** Migration 0070 adds `cp_directive_final_ack_target(uuid)`: SECURITY DEFINER, fixed `search_path`, read-only, EXECUTE granted to `rmt_app` only. It returns tenant, device id, key fingerprint, kind, state, `updated_at`, the database clock and the machine's STORED public key, and only for `kind = 'uninstall'`. The handler verifies the signature against that key and the row's fingerprint (tenant, device, directive id are the row's), then applies with the ordinary `ApplyAck` inside the tenant (RLS) transaction, audited exactly like the signaling path plus `channel: "final_ack"` in the audit detail. If the machine's key no longer matches the directive's key fingerprint at lookup, the answer is the generic 404 below (the caller has not proven anything); only a rotation detected inside the apply transaction, after a valid signature, is 409 refused.
- **Only terminal removal results.** `to` must be `complete` or `failed` (the agent's reportable terminal states for a removal); anything else is 409 refused. Everything else is the normal transition table (`from` must match, `ts_ms` strictly newer and recent, replays are no-ops). `complete` has the identical machine effect as the signaling path (status `removed`, tombstone).
- **Window.** Accepted while the directive is active (including `removal_unconfirmed`, which the sweeper concludes and a genuine completion may still resolve), and for 7 days after it reached `complete` or `failed`; inside the window an exact replay answers `replay`. After that 410 (the helper follows its bounded policy). Cancelled / expired directives never carried a removal result and answer 410, and so does a FORGOTTEN one (an Owner closed it with its machine, section 8: never open, however recent, whatever the result says). The window is judged twice: by the route against its lookup snapshot (a fast path), and again inside the apply on the LOCKED row and the store / database clock, before the replay branch and before any write; a window that closes between the two answers 410 with nothing applied and no audit row.
- **Wire answers.** 200 `{"outcome":"applied"|"replay","state":S}`; 409 `{"outcome":"refused","state":S,"error":...}` (bad transition or `from`, stale or future `ts_ms`, non-terminal `to`, or a key rotated between the lookup and the apply); 410 window passed, or the directive was closed by an Owner's forget (section 8); 429 rate limited (`Retry-After`); 400 malformed body (strict decode: unknown fields such as `device_id` are rejected). EVERY pre-authentication failure is the same answer, status AND body: 404 `{"error":"unknown directive"}` for an unknown id, a malformed id, a non-uninstall directive, a bad signature, another device's key, and a key that no longer matches the directive's fingerprint. A malformed id is rejected early on syntax alone (which says nothing about which ids exist). Every request with a well-formed id makes exactly one ed25519 verifier call over a preimage built the same way (a fixed dummy key, signature and fingerprint stand in when there is no usable stored value), so a known id does not visibly do more work; residual timing differences (a variable-time verifier, the lookup) are bounded by the per-IP throttle and total-volume cap, not claimed to be zero. Each counts as a throttle failure. Only a request that proved possession of the device key can see the directive's state in an answer (200, 409, 410).
- **Replay.** An exact resend of an applied ack answers `replay` for the whole window: the timestamp-freshness rule guards only NEW transitions, and a replay writes no audit row and changes nothing. The key and fingerprint are re-checked INSIDE the apply transaction under the machine row lock (for `failed` too), so a key rotated between the lookup and the apply is refused and nothing is applied.
- **Replay is destination-state idempotence, by design.** A validly signed ack whose `to` equals the directive's current state answers `replay` even if its `from`, `ts_ms` or `detail` differ from the ack that was applied (the helper re-signs after 30 minutes and must still learn that the result was applied; the signaling path has the same semantics). A differing `detail` on a replay is NOT recorded: the stored detail and the audit trail are those of the first applied ack, and a replay writes nothing.
- **Rate limiting.** Two bounds per client IP (trusted-proxy aware): the failure throttle (`directive-final-ack`, 5 free then backoff; 400/404 count, a success resets) and a total-volume cap on ALL requests, successes included (token bucket, 30 requests, refilling 30 per 10 minutes; per-process memory, like the recording-upload limiter).

**Why this does not weaken D-C9.** The tombstone is about the device: a removed machine never registers, never shows presence, never gets directives or sessions, its identity lookup (`cp_machine_identity_by_device_id`) and enrollment of its key stay refused, and `machine.status` never leaves `removed`. This route does none of those things. It cannot deliver a directive, register, create presence or touch a session; it cannot change a machine's status except by applying the one signed completion of an uninstall that was really issued for that exact device key (the same transition the signaling path applies, once: a replay writes nothing). It reads the removed machine's stored key only to verify a signature, and answers only "was my removal result applied". Tests prove that after `complete` the route answers `replay` while identity lookup and enrollment of the key still refuse and the tombstone is unchanged.

## 3. Stages and deploy order

F0 (control plane only) → F1+F2+F3 control plane and signaling (deployed before any agent advertises
`directive_v1`) → F4 agent release → console (confirm dialog, cancel window, second-approver policy).

## 4. Tests

Capability matrix (Owner allowed; Admin, Technician, API token refused); no bulk route; uninstall refused on
an active machine; step-up fresh/stale/absent; token principal refused; self-approval refused when the policy
is on; tenant cap; cancel within the window; expiry and single use (replay → refused by the agent and 409 by
the control plane); tenant isolation; audit-first with a failing audit store leaves no directive and no
delivery; fake = pg. Signaling: relays only to the matching authenticated device, only with the feature.
Agent: bad signature / wrong device / wrong tenant / expired / replayed / no pinned key all refused (each
mutation-checked); non-MSI location refused. VM: real uninstall removes service, files and MSI registration;
a refused directive changes nothing; reinstall preserves identity and rolls back on HealthGate failure.

## 5. Server-side implementation (control plane + signaling, stages F0-F3)

**Review round 2 amendments (binding; server side built and tested)**

- **Dedicated key, enforced.** The control plane refuses to start (`log.Fatalf`) when `DIRECTIVE_SIGNING_SEED`
  derives the same public key as the grant issuer (which also signs elevation grants, session policies and
  session-end artifacts); `CheckDirectiveKeyDistinct` takes every signer key the process holds.
- **Approval.** The approver needs a fresh step-up like the requester. Approval RESTARTS the cancel window
  (`not_before = max(not_before, approved_at + 15 min)`), so it never issues immediately and anyone covering the
  machine can still cancel; an approval that would leave no full window before the request expires is refused
  (410) rather than extending the lifetime. The request TTL is **1 hour** (`directiveRequestTTL`), not 24.
- **Reinstall.** Refused on a `retired` or `removed` machine (a retired agent can only be removed, never
  repaired back into service; 409). A tenant-wide cap of **20 reinstalls/hour** (`DefaultReinstallHourlyCap`)
  joins the per-device 3/day, counted at request and again at issuance.
- **Credentials re-checked at issuance.** Each directive records, for the requester and the approver, the
  session id, the credential epoch (`user_credential.updated_at`) and the mfa generation they acted under.
  Issuance cancels the directive when the session is no longer live (`SessionStore.SessionLive`), the epoch
  moved (password change) or the mfa generation moved (reset / re-enrollment).
- **Ack replay.** `agent_directive.last_ack_ts_ms` persists the last accepted ack timestamp: a new transition
  needs a strictly larger `ts_ms` and one no older than 1 hour (`directiveAckMaxAge`); a replay of the exact
  transition the row already shows stays a harmless no-op.
- **Sweeper.** `cp_directive_sweep_candidates` no longer offers a request awaiting approval as `issue`, ranks
  explicitly (expire, issue, unconfirmed, renotify; oldest due first inside a rank) and offers `renotify` only
  once the row has been quiet for a minute.
- **Attended redeem** applies the D-C9 tombstone (`KeyTombstoned`) before redeeming: 403 for a removed key.

**Review round 3 amendments (binding; server side built and tested)**

- **One lock for policy and issuance.** `SetPolicy` takes the tenant issuance lock EXCLUSIVELY; every request
  and issuance holds it shared from before it reads the policy until it commits. A policy change (including the
  first one, when no policy row exists) therefore cannot land between an issuance's policy read and its commit.
- **An unresolved removal stays exclusive and guarded.** `removal_unconfirmed` is an ACTIVE state: it keeps the
  one-active-directive-per-machine exclusion and the machine status/group guard (the signed uninstall may
  still be executing). The control plane's outcome (`state`) is kept apart from the last state the AGENT
  reported (`agent_state`); a genuine late `complete`/`failed` bound to that agent state is accepted (the agent
  never learns the control plane's own outcome). Before a completion tombstones the machine the store verifies
  the machine is still the one the directive was issued for (device id and key fingerprint). Reaching the end
  of a removal that never reports is an operator matter: there is deliberately no automatic way out, so a dead
  machine stays retired and un-movable until the agent reports.
- **Quotas count issuance.** A cap counts directives ISSUED in the rolling window (`issued_at`, including ones
  that later expired or failed) plus, for a new request only, the live reservations; issuance counts
  issuances only. Done under the quota lock.
- **Step-up and credential snapshot are one read.** `SessionStore.StepUpSnapshot` returns, from one read of the
  live session, whether the verification is fresh, the exact mfa generation it was made against and the
  credential epoch; the directive records that snapshot (request and approval alike), and issuance cancels it
  when the user's generation has moved.
- **The fake's guard is check-and-act.** Machine validation, directive reservation and guarded machine
  mutations share one lock (the twin of the pg machine row lock).
- **Signaling.** A CP-authenticated RETIRED registration removes the normal incumbent for the device in the
  same critical section (presence and the broker stop seeing it immediately) and closes its socket outside
  the lock; every identity lookup carries a registry sequence number taken before the lookup, and an older
  answer is refused once a newer one published (so a slow ACTIVE answer cannot restore a normal registration).
  Acks from one connection are forwarded by ONE worker through a bounded queue, in the order received.

Status: built and tested; the agent (F4) and the console stages are NOT done. Migration **0068**
(`control-plane/migrations/0068_fleet_directives.sql`; 0066-0068 belong to other branches).

| Spec | Where |
|---|---|
| F0 / D-C1 identity, restricted mode | 0068 redefines `cp_machine_identity_by_device_id` FROM 0055 (suspension, pubkey, ephemeral expiry kept) and returns `status`; `removed` never resolves. `GET /internal/devices/{id}/identity` answers a retired machine only with `?restricted=1` (older signaling keeps refusing it). Signaling registers it restricted: no presence, no brokering, directives and acks only. |
| F1 capability | `CapRemoveAgent` (rbac.go): Owner only, absent from `apiTokenGrantableCaps` (`TestRemoveAgentIsNeverTokenGrantable`). |
| F1 endpoints | `http_directive.go`: `POST /machines/{id}/directives`, `GET /machines/{id}/directives`, `GET /directives/{id}`, `POST /directives/{id}/approve`, `POST /directives/{id}/cancel`, `GET/PUT /tenant/directive-policy`. No bulk route. |
| F1 uninstall gates | retired precondition, fresh step-up at REQUEST time (`SessionStore.MFAFresh`, the first reader of `MFAVerifiedAt`), interactive session only, typed machine name, tenant cap 10/hour, 15-minute cancel window, optional second approver, one active directive per device (partial unique index), reinstall 3/device/day. |
| D-C4 issuance | `DirectiveStore.Issue` under the shared tenant issuance lock re-checks tenant, machine state/key generation, both users' authority on the machine's CURRENT group (`AllowsInGroup`, descendants included), policy version, approval, expiry, quota; a failed re-check ends the directive durably. A DB trigger refuses status/group changes while a directive is active. Audit rows are written in the same transaction, before the state they describe. |
| F2 / D-C3 | `directive_sign.go`: RMTDIRECTIVEv1 with a DEDICATED key from `DIRECTIVE_SIGNING_SEED`; its public key is returned as `directive_pubkey` by `POST /enroll/redeem`. Golden vectors: `crates/protocol/testdata/directive-vectors.json` (regenerate with `UPDATE_DIRECTIVE_VECTORS=1`). |
| F3 / D-C8 | The control plane POSTs signaling's `/internal/devices/{id}/directive-pending` (service token, `CP_SIGNALING_NOTIFY_URL`); signaling fetches `GET /internal/devices/{id}/directives/pending` on authenticated registration and on notify and relays only to the authenticated peer that advertised `directive_v1`. Acks are RMTDIRACKv1, signed by the device key over the STORED row's tenant/device/key-fingerprint/directive id plus the claimed transition; the control plane verifies, validates the transition and answers `applied` / `replay`. |
| D-C6 | States accepted, executing, failed, reboot_pending, complete; the sweeper concludes a silent started removal as `removal_unconfirmed` (machine stays retired) and a silent reinstall as `failed`; a late authenticated `complete` still resolves it. |
| D-C9 | `complete` on an uninstall sets `machine.status = 'removed'` in the same transaction; registration refuses it, `POST /enroll/redeem` refuses its key (`cp_machine_key_removed`); directive rows and audit are kept. |

Deploy order stays: control plane + signaling first (they advertise `directive_v1` only when
`DIRECTIVE_SIGNING_SEED` is set and the directive routes are mounted), then the agent release.
Left for the agent (F4): verify and execute directives, the operation record, the MSI uninstall helper,
signing acks with the device key, pinning `directive_pubkey` / `DIRECTIVE_PUBKEY`, advertising
`directive_v1` in `register_agent.features` and loading the shared vectors. Left for the console:
the confirm dialog, cancel window UI, second-approver policy toggle, the step-up prompt.

## 6. Console (web/viewer) - built

- **What the caller may do comes from `GET /me`** (additive; every existing field is unchanged): `user_id` and
  `capabilities`, a list of `{capability, all_groups, group_ids}` for every capability the caller holds
  (`Grant.ScopeFor`; `group_ids` are the assigned groups plus their descendants, so a machine is covered exactly when
  `all_groups` or its CURRENT `group_id` is listed, which is `Grant.AllowsInGroup`'s answer). The console shows
  "Reinstall agent" (active machines) and "Remove agent..." (retired machines) only when it holds `remove_agent` for
  that machine's group; the policy toggle and the removals view need it anywhere. The server still authorizes every
  call. `TestMeReportsTheUserAndTruthfulCapabilities` compares the list with `Allows` / `AllowsInGroup` for every
  capability and group.
- **`GET /directives?state=active[&limit=N][&before=<next_before>&before_id=<next_before_id>]`** (`remove_agent` holders): the tenant's ACTIVE
  directives (requested, issued, accepted, executing, reboot_pending, removal_unconfirmed), each authorized against its
  machine's CURRENT group (`RequireMachine(CapRemoveAgent)`, the same check as request, approve and cancel; a row the
  caller may not act on is absent), ordered `requested_at DESC, id ASC`, with `machine_name`, `machine_alias` and `machine_status`
  added to each row. `limit` defaults to 100 (max 200); `next_before` + `next_before_id` are the composite keyset cursor (requested_at, id) when more may follow: the next
  page is `requested_at < before OR (requested_at = before AND id > before_id)`, so rows sharing a timestamp are never
  skipped; `before` without `before_id` (or the reverse) is a 400 (the scan is bounded to 10 store pages). The fake
  truncates requested_at to microseconds like timestamptz so the cursor round-trips exactly. The console reads 5
  pages per refresh, shows "More pending removals exist" with a Load more button instead of truncating silently,
  and keeps the panel fresh by polling (15 s; 5 s while a removal is inside its cancel window), re-reading on focus
  and visibility, and showing "Could not refresh - last updated hh:mm:ss" when a refresh fails. Store method `DirectiveStore.ListActive` (fake and pg), SQL state list pinned to
  `DirectiveState.active()`. Tests: `directive_list_test.go` (asymmetric group scope, the current group beats the
  recorded one, per-state, paging, tenant isolation, both backends).
- **Remove dialog** (`FleetDirectives.tsx`): effect in plain words, the machine's name (or alias) typed exactly,
  an authenticator code sent to `POST /auth/step-up` BEFORE `POST /machines/{id}/directives {kind, confirm}`, then
  the 15-minute cancel window with a live countdown and a Cancel button. With the second-approver policy on, the
  dialog shows "waiting for a second approver" (no countdown: approval restarts the window).
- **Pending removals** (under the machines table) reads `GET /directives?state=active` (uninstall rows), so it lists
  removals on machines that are not on screen and shows the machine's name. Approve (own step-up) is hidden from the
  requester by `/me.user_id`; the server's 403 on self-approval stays the backstop (and is all there is on a server
  that predates `user_id`). Cancel only while `requested`. `removal_unconfirmed` reads "the agent has not reported
  back; the machine stays retired and locked until it does, or until an owner forgets it" and offers "Forget this
  machine..." (section 8). Finished directives are not listed here (they are
  history: `GET /machines/{id}/directives`).
- **Policy toggle** "Require a second approver for agent removal (recommended)" with the step-up the server demands.
- **Errors**: `ConsoleApiError` carries the body's `code`; 403 `step_up_required`, 409 conflicts, 410 expiry and 429 caps
  (reinstall: 20/hour tenant, 3/device/day; removal: 10/hour) are worded in `lib/fleet_directives.ts`.

## 7. Agent side as built (F4)

Code: `crates/protocol/src/directive.rs` (verifier, ack signer, vectors), `crates/agent-windows/src/directive*.rs`
(`directive` engine, `directive_pin`, `directive_hub`, `directive_reinstall`, `directive_removal`, `directive_win`), the
update chain (`update_worker`, `update_runner`, `update_state`, `update_feed`) and `anchor.rs` (validated trees, held chains).

**Identity and ledger.** The agent pins the directive key (enroll response `directive_pubkey`, or MSI `DIRECTIVE_PUBKEY`,
set-if-blank, never equal to the grant issuer or update signer key) and advertises `directive_v1` only when one is pinned and the
agent is enrolled. Directive and tenant ids are signed as raw bytes, so the agent keys its ledger and every record by the
CANONICAL (lowercase) id; ids are parsed as bytes (no panic on multibyte input). The single-use ledger is the set of operation
records on disk.

**State machine (one directive at a time, persisted before every side effect).**
`accepted -> executing -> failed | reboot_pending | complete`. `submit` verifies and persists `accepted`; `drive` (also the
crash-resume) advances it. The ack chain `issued->accepted->executing->...` is sent one step at a time; an answer is correlated
with the exact transition it answers (the hub keeps a per-connection FIFO of sends), so a delayed duplicate cannot settle a later
step. A removal is not launched until the control plane has confirmed the chain up to `executing`, and never after the directive
expired (checked immediately before launch, and again by the helper against the real clock).

**Mutual exclusion with auto-update.** One durable lock file (`directive-update.lock`, opened with no sharing) is held by BOTH the
engine (around eligibility check + the `executing` reservation) and the update worker (around its removal check + the `Prelaunch`
reservation). Whoever holds it is the only one deciding; the loser sees the winner's durable reservation and stands down.

**Reinstall.** The engine writes a request marker; the update worker (started via the scheduled task) runs one ordinary attempt at
the current signed ring release with "same version" allowed (`REINSTALL=ALL REINSTALLMODE=vamus` when the product code is
unchanged; the HealthGate ack decides Target vs Previous). The directive id is persisted INSIDE the attempt (the Prelaunch write),
outcomes are recorded per attempt id (`attempt_outcomes`), a `Requested` marker is reconciled against that before another attempt
is offered, and a request that was never made (crash after `reinstall_requested`) is made again.

**Removal (helper copy in a SYSTEM-only temp directory, journaled, restartable).** Phases: re-verify (real clock) -> pre-flight
(product code, per-machine, MSI install location, config tree) -> settle recordings (D-C9 hook: no uploader exists, so local files
are abandoned and counted in the report) -> HOLD the validated install chain (every component plain, trusted owner, no non-admin
write/delete/WRITE_DAC/WRITE_OWNER; ancestors held without delete sharing) -> install the restart task -> journal `MsiStarting` ->
`MsiConfigureProductEx(ABSENT)` -> confirm absent -> delete + VERIFY the config tree and recordings except `identity.key` -> sign and
PERSIST the final `complete` ack -> deliver it -> delete `identity.key` and the root -> remove the task, journal and helper.
**Recovery task:** `\DeskRally\RemovalResume-<directive id>`, SYSTEM, at boot (+1 min) and every 10 minutes, definition via XML
(command and argument are separate elements; no shell), pointing at the helper copy. The journal in the helper directory says where
a restart resumes; reboot-required removals acknowledge `reboot_pending` and finish after the reboot. A crash before the MSI call
fails safe (product intact, failure reported); the installer is never run twice. A cleanup failure is never `complete`: it is
retried until the deadline and then reported `failed` with the reason.

**Final report: the HTTPS final-ack route (§2b), confirmation is knowable.** A removed device cannot register, so the helper does
NOT use signaling for its FINAL ack. The `complete` ack, and the post-MSI `failed` ack, go to
`POST {control_plane_url}/agent/directives/{id}/final-ack` over HTTPS (origin from the config via the handoff, validated like enrollment;
same TLS trust as the agent's other control-plane calls). The body is exactly `{"from","to","ts_ms","detail","sig"}` (no device id),
signed RMTDIRACKv1 by the device key. The exact ack is persisted before its first send and resent unchanged across restarts (re-signed
only when over 30 minutes old: the control plane answers `replay` for the destination state, so a re-signed resend still confirms).
Answers: **200 `applied`/`replay` is the ONLY confirmation** (`ReportConfirmed{reported: true}`); 409 (and 400) is terminal and not
confirmed; 410 (window passed, or the directive was closed by an Owner's forget, section 8: the helper never parses the body) is terminal and not confirmed; 404 (every pre-authentication failure) is retried up to 3 times across
runs, then terminal and not confirmed; 429 waits `Retry-After` (clamped 1-300 s); 5xx, network failures and a 200 that is not a clear
`applied`/`replay` are retried with backoff and never confirm. A report that ends not-confirmed (409, 410, 404 x3, or the deadline at the
directive's expiry + 24 h) deletes identity and config anyway and ends `unreported`; the control plane keeps showing `removal_unconfirmed`
until an Owner "forget this machine" action (built: section 8). A cleanup that could not be completed is reported the same way as a
persisted `failed` ack and leaves the identity and config for the operator. The interim `reboot_pending` ack still goes over signaling
(the device is registered then). Failures before the MSI call are reported by the surviving agent from the helper's result file.

**§7 addendum (Codex r2): correlation, generations, durable phases.**

- *Answer correlation.* Signaling echoes `from`, `to` and `ts_ms` in every `directive_ack_result` (optional on decode). The engine
  persists every send's timestamp per ack step (`AckStep.sent_ts`; the timestamp is strictly increasing, so it is a unique request
  id) and settles a step only for an answer naming `(directive_id, from, to, ts_ms)` of a send it persisted. An answer without the
  echo is unattributable and ignored; a duplicate for a settled step, or for a step that is not the next outstanding one, changes
  nothing. Nothing is inferred from arrival order.
- *One consumer, generations.* The hub queues answers in arrival order and the pump is the only consumer. Each attachment has a
  generation; every send and every answer carries one, and the queue and the current generation sit under one lock, so an answer from
  a previous connection (or one delayed across a re-attach) is rejected atomically.
- *Helper phases (each persisted before the next):* `MsiStarting` (with the BOOT ID, before the installer) -> `MsiDone` ->
  `CleanupDone` -> `ReportConfirmed` -> `IdentityDeleted` -> `Finished`; `Aborted` for a removal that never ran the installer (or whose
  directive expired during setup: the clock is re-checked immediately before `MsiConfigureProductEx`). `Finished` is written first;
  only then are the restart task and the handoff removed, and a failure of either is propagated and retried. A re-run in `Finished`
  or `Aborted` only removes leftovers.
- *Reboot.* The local reboot requirement (`reboot_required`) is separate from the server-side state (`confirmed_state`). For a reboot
  the installer announced, the exact `reboot_pending` ack is persisted before its first send and resent unchanged; `confirmed_state`
  advances only on an applied/replay answer for that exact ack. A crash after the installer committed (product absent, no `MsiDone`)
  is ambiguous, so a later boot than the journaled one is required before any cleanup (bounded by the report deadline).
- *Agent gone.* A restarted helper derives "the agent no longer exists" from the durable phase before it delivers anything; the helper
  suppresses its own failure delivery only when a surviving agent AND a durable result handoff exist.
- *Identity deletion.* The agent root's pre-flight identity is journaled; the identity and root are deleted only after reopening the root
  and requiring that identity, requiring that only `identity.key` remains, through validated handles. An already-absent identity or root is
  success only in finalization recovery (`ReportConfirmed` onward).
- *Locations.* The helper directory lives under `%SystemRoot%\System32\config\systemprofile\AppData\Local` (every ancestor
  SYSTEM/Administrators/TrustedInstaller only), not `%SystemRoot%\Temp` (Users create there and, on the measured machine, Everyone has
  full control). The restart task carries an explicit protected SDDL `D:P(A;;FA;;;SY)(A;;FA;;;BA)`.

**§7 addendum (Codex r3).** (1) *Leftover order:* the handoff (identity seed, what the restart task needs) is deleted FIRST and the restart
task LAST; a handoff that cannot be deleted keeps the task. If the handoff is already gone when the task fires, the helper's FINISHED-ONLY
entry point (`run_leftovers_only`) reads only the journal and, when it says `Finished` or `Aborted`, removes the task and the helper copy; in
any other phase it touches nothing. (2) *Reboot gate:* `complete` is never generated before a later boot satisfies a required (or possibly
required) reboot. If the report deadline passes with the boot unchanged, the helper reports `failed` ("a reboot that was not observed"), cleans
nothing and leaves the identity and config for the operator (chosen over `unreported`, which would delete them). (3) *Task presence* is judged
from the task's definition file under `System32\Tasks` (language-independent): only NotFound is "absent", every other failure propagates, and
after `/Delete` the task must be verifiably gone.

## 8. Forget this machine (the Owner's last resort for a removal that will never be confirmed)

**Why.** A removal can stay `removal_unconfirmed` forever: the agent's final ack never arrived (a reboot, the network, the machine was wiped) and section 2b's route can only confirm what an agent really sends. A retired machine may also simply be gone. Until now such a machine stayed "retired and locked" and its removal showed as pending for good. An Owner needs a deliberate, irreversible way to finish it: **forget this machine**. It uninstalls nothing on the machine; it makes the control plane forget the machine.

**Decisions (the coordinator's; binding).**

- **Who.** The removal's own authority: `CapRemoveAgent` (Owner preset only, never API-token grantable) for the machine's CURRENT group (`AllowsInGroup`, descendants included), an interactive session with a TOTP step-up inside 10 minutes (`directiveStepUpMaxAge`, the one the uninstall uses; token principals refused), and the machine's name typed exactly (hostname or the tenant's alias, trimmed, case-sensitive: `machineNameConfirmed`, now the one rule behind both the uninstall request and the forget). Not subject to the tenant's "second approver" policy: nothing is uninstalled, and the gates above are the removal's own minus the approver.
- **When.** Only a machine whose status is `retired` (retire first, then forget: two deliberate steps). Active or quarantined: 409. Already `removed` (a confirmed removal or an earlier forget): idempotent, 200 with the current state and NOTHING written.
- **Effect.** EXACTLY the D-C9 tombstone a confirmed removal applies: `machine.status = 'removed'`, terminal. The device id and the key stay on the row, so identity lookup, registration, enrollment of the key (`cp_machine_key_removed`) and attended redeem refuse them (403 for enrollment and redeem); a reinstall enrolls only as a NEW machine through a fresh enrollment token (a new key and a server-minted device id). There is ONE tombstone statement, `tombstoneMachineTx` (the fake's twin: `tombstoneMachine`), run by both `ApplyAckVia` (a confirmed completion) and `ForgetMachine`. What differs is the record: the audit row is `machine.forgotten`, never `machine.removed`; every forget row carries `agent_confirmed: false`; nothing claims the agent confirmed anything.
- **Directive closure.** Every directive still ACTIVE on the machine stops being active in the same transaction (at most one: `agent_directive_one_active`). The pending-removals panel reads `GET /directives?state=active`, so the row disappears; the machine's history (`GET /machines/{id}/directives`) keeps it.
- **Atomicity.** The audit rows, the closure and the tombstone commit together or not at all, under the machine row lock (`FOR UPDATE`), in the order the rest of the package locks: machine, directive, audit chain. A failing audit store fails the forget and leaves the machine and its directive exactly as they were.

**The HTTP contract.** `POST /machines/{id}/forget`, body `{"confirm":"<name or alias>"}`, mounted with the other directive routes (so only where `DIRECTIVE_SIGNING_SEED` is set). The checks run in this order, so a refusal never reveals more than the one before it:

| Answer | When |
|---|---|
| 404 `unknown machine` | no such machine in the caller's tenant (another tenant's id answers identically; a malformed id too) |
| 403 | no `remove_agent` for the machine's group (Admin, Technician, read-only, an API token holding any grantable capabilities, a group scope elsewhere); or not an interactive session (a token carrying the capability) |
| 400 | malformed or missing body |
| 200 `{"outcome":"already_removed","machine":M,"closed_directives":[]}` | the machine is already `removed`: the current state, no second audit row, no confirmation or step-up needed (nothing changes) |
| 409 `a machine can only be forgotten after it is retired` | active or quarantined |
| 422 `type the machine's name to confirm that it is forgotten` | the typed confirmation is not the name or alias |
| 403 `{"code":"step_up_required"}` | no TOTP verification in this session within 10 minutes |
| 200 `{"outcome":"forgotten","machine":M,"closed_directives":[D...]}` | done: `M.status` is `removed`, each `D` is the directive as it is now (`state: "forgotten"`) |
| 409 `machine changed since it was authorized; retry` | the machine moved to another group between the handler's read and the store's lock (the store re-validates everything under the lock: unknown id, already removed, group, retired) |
| 500 | the store failed (the audit store down included): nothing was written |

**The new directive state `forgotten`** (migration 0073: the two CHECK constraints on `agent_directive` widen; no function is redefined and no SECURITY DEFINER function is added). It is CONTROL-PLANE-ONLY, like `removal_unconfirmed`, and terminal. No existing state fits: `complete` would say the agent confirmed; `failed` is agent-reportable, and the final-ack route answers `replay` to a repeated `failed`, which would read as the agent's failure being recorded; `cancelled` says "cancelled before anything was sent", false for a removal that was issued or even executed. Agents never receive or report it:

- the agent's reportable states are the closed list in `crates/protocol/src/directive.rs` (`state::*`, `transition_allowed`), and `sign_ack` refuses every other pair, so the agent cannot sign a transition to or from `forgotten`;
- the control plane's `directiveTransitionAllowed` names `forgotten` as neither source nor target (`TestNoAcknowledgementCanReachOrLeaveForgotten` walks every pair, then tries it through the signaling route and straight at the store);
- a directive reaches an agent only as its signed artifact (`pendingDirectiveWire{directive_id, artifact}`; `PendingForDevice` serves only issued, accepted, executing and reboot_pending rows; a closed directive keeps its artifact as evidence, so `TestAForgottenDirectiveIsNeverServedToADevice` asks both stores directly), and signaling's `Directive` and `DirectiveAckResult` messages carry no control-plane state (the result echoes only the agent's own `from`, `to`, `ts_ms`);
- the agent's final-ack classifier (`classify_final_ack_response`) reads the HTTP status and, for a 200, `outcome`; it never parses `state`.

**The agent's LATE final ack.** The agent really did finish the removal, and its signed final ack (section 2b) arrives after the Owner forgot the machine. After the signature check (an unproven caller still gets the one generic 404) the route answers **410** `this removal was closed when an owner forgot the machine; no result was recorded` for ANY `to` (`complete`, `failed`, anything else): never 200, so never `replay` or `applied`, which the agent would read as confirmation. The agent's helper treats 410 as terminal and not confirmed, deletes its identity and ends `unreported`, which is the truth. Nothing is applied, nothing is written, and the tombstone is untouched. It is judged twice: by the route against its lookup snapshot, and again in `ApplyAckVia` on the LOCKED row (a forget that lands between the two reads `forgotten` there and answers the same 410: `TestForgetBetweenTheFinalAckLookupAndApply`). The signaling path cannot be reached at all: the identity lookup refuses a removed device, so its `directive_ack` is answered `refused` (404 from the control plane). The store refuses a `forgotten` source on either channel (`ErrDirectiveBadTransition`, `ErrDirectiveFinalAckWindowClosed`), so no future route can resurrect it by accident, and `finalAckWindowOpen` is false for `forgotten` however recent.

**A live restricted connection.** A retired machine may hold a restricted signaling connection (only `directive_ack` is allowed on it). No new signaling protocol and no new internal route: signaling already re-resolves EVERY registered peer, restricted ones included, every 60 seconds with its cache bypassed (`RevalidateAgents`), and drops one the control plane answers 404 for (`dropAgent`: registry entry removed, socket closed with a policy-violation frame). A removed machine is exactly that answer (`cp_machine_identity_by_device_id` refuses `removed`), so the connection goes within one interval, the same way it does for a machine removed by a confirmed completion (`TestRevalidateRestrictedPeers`, the 404 case). Until then the connection is inert: its identity no longer resolves at the control plane, so a pending fetch is 404 and an ack is 404 (signaling's 60-second positive identity cache can admit a re-registration as a restricted peer for that long, equally inert, and the next sweep drops it; after that a registration is refused outright).

**Races (both orders, two real Postgres connections).** The forget locks the machine row `FOR UPDATE`; a request and an issuance lock it `FOR SHARE` and a final-ack apply `FOR UPDATE`, so each pair serializes and whichever commits first is seen by the other. Held-open transactions (`testAfterForgetLock`, `testAfterAckLock`, the existing `testAfterPolicyRead`) prove it. An issuance in flight makes the forget wait and then close the now-issued directive (`directive.issued` precedes `machine.forgotten`). A forget in flight makes an issuance wait and then find the directive forgotten, so it is never signed and signaling is never notified. A final-ack `complete` in flight makes the forget wait and then answer `already_removed` with no forget row (the agent's confirmed removal won). A forget in flight makes a final-ack `complete` wait and then answer 410 (the Owner's decision won). An un-retire that arrives while a forget holds the machine waits and then meets the terminal tombstone (`ErrMachineRemoved`). Randomized races check the invariants in both backends: a forget against a final-ack `complete` (machine removed, directive exactly one of `complete` or `forgotten`, the trail agrees) and two Owners forgetting at once (one forgets, the other is told `already_removed`, one set of audit rows).

**Audit.** `machine.forgotten` (actor: the Owner; target: the machine; metadata: `machine_id`, `device_id`, `group_id`, `key_fp`, `previous_status`, `agent_confirmed: false`, and, when a directive was closed, `closed_directives: [{directive_id, kind, state}]` with the state it was in) is written first, then one `directive.forgotten` per closed directive (target: the directive; metadata: `from`, `state: "forgotten"`, `reason: "machine_forgotten"`, `agent_confirmed: false`). The directive row keeps what the AGENT reported (`agent_state`, `acked_at`); its `state_detail` becomes the control plane's own words. A forget of an already removed machine writes nothing.

**Console (web/viewer).** "Forget this machine..." sits next to "Remove agent..." on every RETIRED machine, shown only when `/me` says the caller holds `remove_agent` for that machine's group (the same `holdsCapabilityForGroup` answer as Remove: `canOfferForget`), and on a pending-removals row in `removal_unconfirmed` whose machine is still retired (`canForgetFromRemoval`; that list holds only rows the caller may act on, and the server authorizes the call anyway). Both open `ForgetMachineDialog` (`FleetDirectives.tsx`): the effect in plain words (`forgetDialogCopy`: it permanently removes NAME from DeskRally; the machine can never reconnect with its current identity and this cannot be undone; reinstalling the agent enrolls it as a new machine; use it when the machine is gone or its removal will never be confirmed; it does NOT uninstall anything on the machine), the machine's name typed exactly (the removal's own `removalConfirmationMatches`, re-checked at submit), the authenticator code sent to `POST /auth/step-up`, and only then `POST /machines/{id}/forget`. Afterwards the host re-lists the machines (the row reads `removed`, and a removed machine shows no status dropdown: it has no status to choose, and a select matching none of its options read "active") and re-reads the pending removals (the closed removal is gone). `already_removed` is reported as "already removed. Nothing changed." The state `forgotten` has its own label and words ("Closed when an owner forgot this machine. The agent never confirmed the removal."), and `removal_unconfirmed`'s explanation now names the way out ("...or until an owner forgets it"; the in-app help says the same). The refusals are worded in `friendlyDirectiveError` (step-up, retire first, the machine moved, the typed name). Tests: `fleet_directives.test.ts` (offer rules, wording, errors), `console_api.test.ts` (the client call), `e2e/forget_machine.spec.ts` (the dialog flow against a mocked API, like `fleet_directives.spec.ts`).

**Not done, on purpose.** Forget uninstalls nothing, deletes no recordings and does not touch the machine; the agent, if it still exists, is simply refused from then on. There is no bulk form (the removal's own rule). There is no per-tenant rate cap (the removal's 10/hour counts issued uninstalls; a forget needs an Owner, a fresh TOTP code and the typed name each time). The machine stays in the machine list as `removed` (history), and a removed machine's group is as movable as a confirmed removal's has always been.
