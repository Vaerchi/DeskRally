# docs/51: Session transfer and escalation

**Status:** design ACCEPTED by Codex (round 4), 2026-10-21; implementation next. Read §7–§9 as superseding §3–§5 where they differ. It closes the parity item "§7 P1 Session transfer / escalation to another tech or group" (checklist re-check 2026-10-21: not built).

## 1. What it is

A technician in a live unattended session hands it to:
- **a named colleague** (transfer), or
- **anyone who may start sessions in the machine's group** (escalation to a group).

The receiver accepts from the console and lands in a live session on that machine. The sender's session ends, and the sender's viewer says why ("transferred to Bob").

Out of scope:
- attended sessions, which already hand off on connect (`AttendedStore.ReassignTechnician`);
- observers (view-only sessions are not transferable);
- inviting a second participant into the same session, which is a separate item.

## 2. Why a handoff, not a mutation

A live session is bound to one technician in five places, and four of them cannot change mid-session without an agent change:

| Where | Binding | Mutable? |
|---|---|---|
| Control plane | `session_record.technician_id` (NOT NULL; nothing writes it after creation; `audit.go` relies on that) | could be |
| Signaling | the signed ticket's `technician_id`, single use per `session_id` (`session_ticket_redemption`) | no: a new ticket for the same session id collides |
| Agent | the technician is read once per peer connection from `Brokered` | no |
| Agent audit chain | the technician is sealed into the chain; `adopt_identity` refuses renames | no |
| Agent backstage grants | must match the brokered technician (`grant_matches_live_session`) | no |

So a transfer is: **end session S1 (A's) and start session S2 (B's) on the same machine, atomically, with S2 linked to S1.** B's session is an ordinary new session: new ticket, new peer connection, new audit chain. It needs **no agent change**, so every deployed agent supports it.

## 3. Data

Migration `0060_session_transfer.sql`:

```sql
CREATE TABLE session_transfer (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenant(id),
  session_id    uuid NOT NULL,                 -- S1, the session being handed off
  machine_id    uuid NOT NULL,
  group_id      uuid,                          -- S1's admission group (RBAC scope)
  from_user_id  uuid NOT NULL REFERENCES app_user(id),
  to_user_id    uuid REFERENCES app_user(id),  -- NULL = escalate to anyone in the group
  note          text NOT NULL DEFAULT '' CHECK (length(note) <= 500),
  state         text NOT NULL CHECK (state IN ('pending','accepted','cancelled','expired','superseded')),
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,          -- created_at + 5 min
  accepted_by   uuid REFERENCES app_user(id),
  new_session_id uuid,                         -- S2
  FOREIGN KEY (tenant_id, session_id) REFERENCES session_record(tenant_id, id)  -- composite: no cross-tenant link
);
-- At most one live offer per session.
CREATE UNIQUE INDEX session_transfer_one_pending ON session_transfer (tenant_id, session_id) WHERE state = 'pending';
ALTER TABLE session_record ADD COLUMN transferred_from uuid;   -- S2 -> S1
ALTER TABLE session_record ADD COLUMN end_reason text;          -- 'transferred' for S1 (NULL = as before)
```

- RLS on `session_transfer` follows `session_record`'s tenant policy.
- The composite FK follows the house rule "composite FK closes cross-tenant write".

## 4. API (control plane)

| Route | Who | Effect |
|---|---|---|
| `POST /sessions/{id}/transfer` `{to_user_id?, note?}` | S1's **holder** only (`checkHeldSession`); S1 open, `access='control'` | Creates a pending offer (supersedes an older pending one). `to_user_id` must be an active user of the tenant who holds `CapStartSession` in S1's group, else 422. Audit `session.transfer_offered`. |
| `DELETE /session-transfers/{id}` | the offer's sender | `cancelled`. Audit. |
| `GET /session-transfers/incoming` | any user | Pending, unexpired offers: those addressed to me, plus group escalations in groups where I hold `CapStartSession`. Never my own offers. |
| `GET /session-transfers/outgoing` | any user | My pending offers (for the sender's "waiting for Bob…" state). |
| `POST /session-transfers/{id}/accept` | the addressee, or (group offer) anyone with `CapStartSession` in the group; never the sender | In ONE transaction: lock the offer row and S1; require offer `pending` + unexpired and S1 open; end S1 (`ended_at=now`, `end_reason='transferred'`); create S2 (`technician_id=acceptor`, same machine/group, `access='control'`, `transferred_from=S1`) through the SAME admission checks as `POST /sessions` (machine not quarantined, group policy, seat caps counted AFTER S1 ends); mark the offer accepted. Then mint the ticket (and the initial policy) exactly as `POST /sessions` does and return the same response body. Audit `session.transfer_accepted` (from, to, S1, S2) plus the normal `session.start` for S2. |

Rules:
- **Expiry:** offers expire after 5 minutes (checked on read and on accept; the reaper marks them `expired`). If S1 ends for any other reason, its pending offer becomes unusable (accept requires S1 open).
- **The holder check stays exactly as it is.** A transfer never lets B act on S1; B only ever holds S2.
- **Renewals after a transfer:** S1's lease renewal refuses with **409 `{"error":"session transferred","transferred_to":"<display name>"}`** instead of the generic ended error, so A's viewer can say why. The agent's lease for S1 lapses within its TTL. B's new connection is a separate peer and does not wait for that (multi-session agents).
- **Old agents:** S2 is a second concurrent session to the same machine for up to one lease TTL. Agents before 0.1.3 are single-session, so accept refuses them with 422 "the machine's agent is too old to hand off a live session" (same version gate as observers).
- `audit.go`'s comment ("there is no session-transfer feature") is revised. Its invariant (a record's technician never changes) still HOLDS, because S1 keeps A and S2 has B.

## 5. Console (viewer)

- **Sender:** a "Transfer…" item in the session menu (control sessions only) opens a dialog listing eligible technicians (from a new `GET /sessions/{id}/transfer-candidates`, which applies the same rule as the 422), plus "Anyone in <group>". It has an optional note and Send. While pending, a banner reads "Waiting for Bob to accept · Cancel". On the 409 "session transferred", the session view closes with "Session transferred to Bob".
- **Receiver:** the console polls `GET /session-transfers/incoming` every 10 s while signed in. A badge and toast show "Alice wants to hand you <machine> · Accept / Decline (ignore)". Accept calls `/accept` and connects with the returned ticket through the normal brokered-connect path.
- No push channel is added; polling at 10 s matches the lease cadence.

## 6. Tests

**Go (unit + PG under RLS):**
- offer/cancel/supersede;
- only the holder can offer;
- an addressee that is ineligible gives 422;
- accept by the wrong user gives 403; the sender cannot accept;
- accept after expiry or after S1 ended gives 409;
- **atomicity:** S1 ended and S2 created together, or neither, under concurrent double-accept (exactly one wins);
- seat cap: a full tenant still lets a transfer through (S1 ends first);
- S1 renew gives 409 "session transferred";
- tenant isolation (an offer in another tenant is invisible and unacceptable);
- group escalation visible only to holders of `CapStartSession` in the group;
- old-agent refusal.

**Viewer:**
- vitest for the dialog, the incoming poller, the banner and the 409 message;
- a mocked-API Playwright spec walking sender and receiver.

**Live:** a fixture e2e with two technicians on one real agent (the pass-16 fixture already has tech A and B): A connects, offers to B, B accepts and receives video, and A's view closes with the transferred message.

## 7. Design review v1: REPAIR, resolved here (v2)

Codex review of the design raised 4 high and 2 medium findings. v2 binds the following; where it differs from §3–§5, v2 wins.

1. **Authorization is re-derived, never cached.**
   - **At offer:** the sender must be S1's holder (`checkHeldSession`). The named recipient must be an active member of the tenant who holds `CapStartSession` on the machine's CURRENT group.
   - **At accept:** the acceptor must not be the sender. They must be an active tenant member, and the ordinary `POST /sessions` authorization and policy checks run on the machine as it is NOW (current group, quarantine, group policy, observer/agent-version gate). That covers named recipients too. A machine whose group changed since the offer, or that has no group, is judged like any new start; a null group is never "unrestricted".
   - **Listings:** `incoming` re-checks `CapStartSession` per offer before returning any machine name or note. `transfer-candidates` requires S1's holder.
   - An offer id is never a bearer credential; the acceptor is the authenticated caller.
2. **Tenant-qualified references everywhere.**
   - `session_transfer` uses composite FKs `(tenant_id, x)` for `session_id`, `machine_id`, `group_id` and `new_session_id`, and for `session_record.transferred_from`. Users are referenced through the tenant-membership key, so an offer can never name another tenant's user.
   - `machine_id`, `group_id` and `from_user_id` are DERIVED from the locked S1 row, never taken from the request.
   - A CHECK ties state to fields: `accepted` ⇔ `accepted_by` AND `new_session_id` are non-null.
   - Rows are updated only through state-conditional `UPDATE … WHERE state='pending'`.
3. **One admission protocol.**
   - The count-and-insert body of `StartSessionWithinLimit` becomes `admitSessionTx(ctx, tx, tenant, rec, limits)`, used by BOTH `POST /sessions` and accept.
   - Accept, in one `withTenant` tx: take the same per-tenant advisory lock FIRST, as every start does; `SELECT … FOR UPDATE` the offer, then S1; revalidate (offer `pending`, `expires_at > now()` in DB time, S1 open); end S1 (`end_reason='transferred'`); `admitSessionTx` for S2 (counts see S1 ended); mark the offer accepted; write the management audit rows.
   - Any failure rolls back everything, S1's end included.
   - `POST /sessions/{id}/end` and the reapers are single conditional UPDATEs on `ended_at IS NULL`. Racing an accept, either the end wins (accept then sees S1 closed and refuses) or the accept wins (the end then finds S1 already ended). Tests cover transfer vs start, end, renew, reap and double accept.
4. **The overlap is an explicit, bounded, tested property, and fail-closed where it cannot be bounded.**
   - After accept, A's agent-side session lives until its lease lapses: at most the policy TTL (30 s) plus `LEASE_TICK` (2 s). That is exactly the revocation bound the product already documents for "End session" (docs/25 F03).
   - On lapse the agent ends S1's session loop. Its peer, input sender, backstage grants and installed policy are all per-session state and are dropped with it. Elevation grants are single-use and bound to S1's session id.
   - The bound only exists if the agent ENFORCES leases, so accept is REFUSED (422 "this machine's agent does not enforce session leases; end the session and let your colleague connect") unless S1 has had at least one successful lease renewal. A new `session_record.lease_renewed_at` is set by `POST /sessions/{id}/policy`. A renewal only happens when the agent asked for a lease, which proves enforcement.
   - The live e2e measures A's agent-side end and asserts it within TTL + tick.
   - The claim "every deployed agent supports it" is withdrawn: lease-enforcing agents of version 0.1.3 or later.
5. **Accept is idempotent and recoverable.**
   - A repeat `accept` by the same acceptor on an `accepted` offer whose S2 is still open returns S2 with a FRESHLY minted ticket. The ledger is keyed on redemption, so an unredeemed ticket is simply superseded, and a redeemed one makes the old connection the live one, as for any reconnect.
   - The response distinguishes "transaction failed (nothing changed)" from "handed off; connect with this ticket".
6. **Audit.**
   - These management-audit rows are written INSIDE the accept tx: `session.transfer_accepted` (transfer id, from, to, S1, S2, machine, group), `session.end` for S1 (`reason: transferred`, actor = acceptor, `via_transfer`), and `session.start` for S2 (`transferred_from`).
   - Cancel, supersede and expiry are audited with their actor (the system for expiry).
   - Agent chains stay separate, one per session. The CP rows link S1 and S2 by id. The ACTUAL agent-side end of S1 is recorded separately by the docs/49 end report (`lease_lapsed`).

## 8. Design review v2: REPAIR on items 4 and 5, resolved here (v3; supersedes those items)

**4'. B's session starts only after the AGENT has reported S1 ended. No overlap; no inferred enforcement.**
- `lease_renewed_at` is dropped. A renewal does not prove the agent enforces leases.
- The proof used instead is the agent's own end report (docs/49 `session_ended`). The agent sends it over its authenticated signaling connection, signaling forwards it as the vouched session, and the CP accepts it at `/internal/sessions/{id}/ended`. It is the only authoritative statement that S1 no longer exists on the machine.

The flow:
1. **Accept** (one tx, under the same per-tenant admission lock): revalidate as in §7.1; the offer goes `pending → releasing` (`accepted_by = acceptor`, `releasing_at = now()`).
   - S1 stays OPEN and keeps its seat.
   - S1's renewals now refuse with 409 `session transferred`, so A's viewer closes within one renewal interval (about 10 s) and the agent reports `viewer_left`. If A's viewer does not cooperate, the lease lapses and the agent reports `lease_lapsed` within TTL + `LEASE_TICK` (about 32 s).
   - Audit `session.transfer_accepted`.
2. **Finalize** (`finalizeTransferIfReleased`, one tx, same lock order): it runs when the CP records S1's agent end report (inside `handleSessionEnded`), and also when the acceptor polls.
   - Condition: the offer is `releasing`, and `session_record.agent_ended_at` (new; set only by the authenticated end report) is non-null for S1.
   - It ends S1 if still open (`end_reason='transferred'`), admits S2 with `admitSessionTx` (the counts see S1 ended), and moves the offer to `accepted` (`new_session_id`), all in the same tx. Audit `session.end` for S1 and `session.start` for S2 (`transferred_from`).
   - If S2's admission fails (for example the group policy changed in between), the offer goes `failed` with the reason. S1 is already gone on the agent, so nothing reconnects silently, and B is told why.
3. **Ticket:** B's console polls `GET /session-transfers/{id}` (acceptor only). Once `accepted`, it calls `POST /session-transfers/{id}/ticket`, which mints S2's ticket (and initial policy) exactly as `POST /sessions` does. The acceptor only; S2 must be open.
4. **Timeout:** if no end report has arrived 60 s after `releasing_at`, the offer goes `failed` ("the machine did not confirm the previous session closed"). Nothing is worse than before the offer: S1's renewals stay refused, so S1 ends on lease-enforcing agents, and on any other agent A keeps exactly the access A already had.

**Gate:** offers are refused unless the machine's agent is 0.1.6 or later (docs/49 end reports for every reason: `viewer_left`, `lease_lapsed`, `service_stop` and others), and S1 is signaling-vouched (has a control-plane session; the end report needs it). Older agents get 422 "update this machine's agent to hand off a live session".

**5'. Recovery is split at redemption.**
- **Before S2's ticket is redeemed:** `POST /session-transfers/{id}/ticket` is idempotent. It re-mints a fresh ticket while S2 is open and its id has no redemption row; the unredeemed earlier ticket is simply superseded.
- **After redemption:** the transfer is complete, and B is S2's holder. A lost or failed connection is recovered by the viewer's EXISTING SessionRecovery path, which re-verifies S2, ends it, and starts an ordinary new session with `POST /sessions`, which B may do with the same authority accept already required. The ticket endpoint answers 409 `already connected; reconnect` so the console takes that path. No second redemption of S2's id is ever attempted.
- **Tests:** a lost accept response before redemption gives the same S2 and a fresh ticket; after redemption it gives 409 and recovery through `POST /sessions`; a failed original peer is recovered the same way.

New columns: `session_transfer.releasing_at`, the states `releasing` and `failed` (with `failure_reason`), and `session_record.agent_ended_at`, which the docs/49 end-report handler sets.
## 9. Design review v3: REPAIR (2 high, 1 medium), resolved here (v4)

1. **One live transfer per session, and per-state invariants.**
   - The unique index is `(tenant_id, session_id) WHERE state IN ('pending','releasing')`. Creating an offer while S1 has a releasing transfer is refused (409).
   - The per-state CHECK constraints:

     | State | Required |
     |---|---|
     | `pending` | `accepted_by`, `new_session_id` and `failure_reason` all NULL |
     | `releasing` | `accepted_by` and `releasing_at` NOT NULL; `new_session_id` NULL |
     | `accepted` | `accepted_by` and `new_session_id` NOT NULL |
     | `failed` | `failure_reason` NOT NULL |
     | `cancelled`, `expired`, `superseded` | `new_session_id` NULL |

   - Tests cover a concurrent offer and accept while releasing.
2. **Finalize re-runs the FULL authorization, serialized like a new start.** Under the admission lock, in the order admission lock → offer → S1, finalize re-checks:
   - the acceptor's active tenant membership;
   - `CapStartSession` on the machine's CURRENT group;
   - quarantine and group policy;
   - the agent gates;

   all before `admitSessionTx`. Any failure leaves the offer `failed` with the reason and creates no S2. Tests cover revoking the acceptor's role, removing the acceptor, and moving the machine to a group the acceptor cannot reach, each during releasing.
3. **A repeated accept is a status read.**
   - An accept by the RECORDED acceptor on `releasing`, `accepted` or `failed` returns the current status (and S2's id when `accepted`) with no mutation and no audit.
   - Expiry applies only to `pending`: `releasing` is governed by the 60 s release timeout.
   - Tests cover a retry before finalize, after finalize, after failure, and after redemption (the ticket endpoint then answers 409 and recovery goes through `POST /sessions`).
4. **End-report handling.**
   - `agent_ended_at` is set idempotently: the first report wins, and duplicates change nothing and do not re-finalize or re-audit.
   - The report handler takes the same lock order before touching S1 or an offer.
   - Terminal states are terminal: a late report after `failed` or `expired` may close S1, but it never revives an offer or admits an S2.
   - An end report committed before accept closes S1, so accept refuses.
**Answers to the open questions:**
1. End S1 at accept; A can Observe separately through normal observer admission.
2. Reuse `CapStartSession` for v1.
3. 5 minutes, enforced in DB time at accept; the reaper is only cleanup.