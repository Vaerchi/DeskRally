# docs/49: ending leaked session rows from the agent's own end report

The protocol uses the agent's authenticated end report with first-writer-wins
updates. Later contract sections supersede earlier descriptions where they differ.
A lease-renewal timestamp alone is not a safe reaping signal: it does not prove agent
enforcement, can race across replicas and can be affected by clock changes. A
`SECURITY DEFINER` function alone also does not bypass FORCE RLS.

This addresses session-policy enforcement that accepted a concurrency cap without requiring
a session lifetime to release it. The cheap half shipped earlier: a concurrency
cap without a lifetime is refused.

## The problem

`session_record.ended_at` is written by:
- `/end`;
- the guest-ended report;
- machine quarantine or retire;
- start-time compensation;
- two age reapers that run only for tenants with `max_session_seconds > 0` (default 0).

Sessions may never reach `/end`: a tab is closed, a browser crashes, a laptop
sleeps. Their rows stay open forever:
- they count against `max_concurrent_sessions`, which has no age filter;
- the console shows them as live;
- reports give them no duration.

## The authoritative signal: the agent knows when a session ends

Every brokered session (controller or observer) runs in one agent session loop
(`crates/agent-windows/src/host.rs`, the per-transport function around :3640), bound to its
control-plane session id (`transport.control_plane_session()`). When that loop exits, the session
is over:
- **Connection lost:** the viewer releases the session (`App.tsx`, "the session has been released;
  reconnect to continue") and a reconnect starts a NEW control-plane session. It never reuses the
  old id.
- **Signaling socket reconnects** (Pass 26) do not end live WebRTC sessions, so they never reach
  this exit.
- **Lease lapse, maximum duration, idle limit, guest End, policy revocation, service stop:** each
  ends the loop, and the session with it.

**The plumbing already exists, for the guest-ended case only:**
- **Agent:** a bounded, retained report queue (`guest_end_reports`) and a worker that sends
  `GuestEndedSession { control_plane_session }` over the authenticated signaling connection. It
  retries until it gets a terminal `GuestEndedResult`.
- **Signaling** (`server/signaling/guestend.go`): it takes the device identity from the
  authenticated connection, never from the message. It forwards to the control plane's
  `POST /internal/sessions/{id}/guest-ended`, authenticated by the device-identity service token.
- **Control plane** (`guest_end.go`, `pgstore_guest_end.go`): `EndSessionForDevice(tenant,
  session, device, at)` ends ONLY that tenant's and device's open row.
  - It is atomic and first-writer-wins: exactly one caller transitions it, and the end and its
    device audit event commit together, or neither does.
  - Already-ended rows keep their timestamp and write no audit.
  - Another device's row returns `other_device`; an invisible row returns `not_found`.

## Design

1. **Agent: report every end, with a reason.**
   - When a session loop with `Some(control_plane_session)` exits for any reason, the agent
     enqueues the existing report with a reason: `guest_ended`, `viewer_left`, `lease_lapsed`,
     `max_duration`, `idle`, `policy`, `service_stop` or `other`. This covers observers too.
   - The guest-End arm keeps `guest_ended`. Every other exit is mapped where the loop already
     knows why it is leaving; anything unclassified becomes `other`, never "no report".
   - A report is sent at most once per session id: the queue already dedups by id.
2. **Wire.**
   - A new signaling message `SessionEnded { control_plane_session, reason }`. The device comes
     from the authenticated connection.
   - Signaling forwards it to a new control-plane route `POST /internal/sessions/{id}/ended`
     carrying `{ device_id, tenant_id, reason }`, with the same service-token auth, throttle and
     strict decoder as `guest-ended`.
   - The result returns as `SessionEndedResult`, and the agent drops the report on a terminal
     outcome.
   - `guest-ended` stays for older agents.
   - Rollout order: control plane and signaling deploy first. An agent that sends `SessionEnded`
     to an older signaling server gets an error result and keeps today's guest-only behaviour.
3. **Control plane: the same store transition, with the reason.**
   - `EndSessionForDevice` gains a `reason` that goes into the audit event (`session.end`, actor =
     the device, `reason`).
   - **`ended_at` is the control plane's receipt time,** not an agent clock. Queue delay makes it
     slightly late, never early.
   - First writer wins exactly as today: a row already ended by `/end`, an admin, quarantine or a
     reaper keeps its timestamp and reason.
   - The reason is an enum validated on input; unknown values become `other`.
4. **Nothing else changes:** no new clock, no cross-tenant SQL, no schema change other than none
   (the audit row carries the reason), no reaper.

## Why it never ends a live session's row

- **Only the agent ending its own session triggers it.** That session's media and input are already
  gone when the report is queued.
- **The device can end only its own rows** in its own tenant (`other_device` / `not_found`). A
  compromised agent gains nothing: it can already end its own sessions by stopping streaming.
- **No timing inference:** a delayed or retried report ends a row that is already over.
- **A viewer reconnect** is a new session id, so a late report for the old id ends only the old row.

## Residuals, stated plainly

- **A report lost before delivery** leaves the row open, as today:
  - the agent crashes or loses power;
  - the agent is uninstalled;
  - the queue overflows (bounded);
  - the machine never reconnects.

  v2 shrinks the leak from ~27% of sessions to these cases. Persisting the queue across restarts is
  a possible follow-up, measured first.
- **Agents older than this release** keep today's behaviour until they update.
- **Existing leaked rows** are not touched by v2. A one-time, operator-run cleanup of rows whose
  device has since re-registered, which proves the old session process is gone, is a separate,
  reviewed step.

## Measurement after rollout

From audit and `session_record`, per day:
- new sessions;
- ended by `/end`, by agent report (per reason), by reapers, or still open after 24 h;
- the agent version of each still-open row.

The target is to reduce still-open-after-24h rows to the crash/uninstall residual on updated agents.

## Tests

- **Agent:** every exit path of the session loop queues exactly one report with the expected reason
  (a table over the exit branches). The guest path is unchanged. No report without a
  control-plane id.
- **Signaling:**
  - `SessionEnded` takes the device from the connection, never the message;
  - an unknown reason is forwarded as `other`;
  - the result is relayed;
  - rate limits are respected.
- **Control plane** (fake and Postgres, the same cases):
  - an open row is ended with the reason audited;
  - an already-ended row keeps its timestamp and writes no audit;
  - `other_device` and `not_found`;
  - concurrent `/end` versus report: exactly one transition and one audit.
- **E2E:** the viewer closes its tab (no `/end`), and the row ends with `viewer_left` within the
  agent's teardown time plus retry.

## Session lifetime, version skew and authority contracts

### 1. One control-plane session id = exactly one agent session lifetime (the high finding)

The invariant rests on three layers, all required before a report is sent:
- **Server side: a session id can be brokered at most once.** A brokered session reaches an agent
  only through a session ticket. Tickets are redeemed against the SHARED single-use ledger
  (`control-plane/ticketredemption.go`), keyed by `tenant_id + session_id` with
  `INSERT … ON CONFLICT DO NOTHING`. With ticket verification on, a control-plane session id is
  brokered to an agent at most once, across every signaling replica.
  - A ticket's own signed expiry (2 min) is shorter than the ledger's retention (expiry + 1 h), so
    an id cannot be re-brokered after its row is purged.
- **The agent reports only for sessions signaling vouched for.** It reports only when the session's
  binding is a signaling-vouched control-plane id (`transport.control_plane_session()` is `Some`,
  the same condition the lease uses). Without ticket verification, for example on a dev server,
  there is no vouched id and no report. Today's behaviour is unchanged there.
- **Agent fence (new):** the signaling mux already refuses a duplicate `Brokered` for a LIVE session
  id (`signaling_mux.rs`). v3 adds a bounded "ended in this process" set:
  - A `Brokered` for an id that already ended is refused and logged.
  - The set holds the last 1024 ids for 24 h, far beyond any ticket's life.
  - A refused re-attach never creates a second lifetime, so the earlier report cannot close a
    live one.
- **Report only after teardown:** the report is queued only after the session loop has stopped
  and joined its media and input tasks, so nothing of the session is still running when its row
  closes.
- **Observers:** each observer is its own control-plane session id with its own ticket and its own
  loop, so the same reasoning applies per id. Another session on the same agent is untouched,
  because the report names one id and the store ends one row.

### 2. Rollout and version skew (medium)

- **Capability negotiation, no blind sends:**
  - Signaling advertises `features: ["session_ended_v1"]` in `Registered`.
  - The agent's `ServerToClient::Registered` is a tagged serde enum without
    `deny_unknown_fields`, so older agents ignore the new field.
  - An agent sends `SessionEnded` ONLY on a connection whose `Registered` advertised the feature.
    Older signaling returns an error for an unknown message type, so the agent never relies on it.
- **Fallback:** on a connection without the feature, the agent sends today's `GuestEndedSession`
  for `guest_ended` reports, and keeps other reports queued for a capable connection. They are
  never silently dropped; queue bounds below.
- **Signaling to control plane:** signaling advertises the feature only when its control plane
  answers the new route. It probes `POST /internal/sessions/<nil-uuid>/ended` at startup and treats
  404 as "not supported".
  - Without the route it does not advertise the feature, so agents fall back. A mixed replica
    therefore cannot strand reports.
  - A control-plane rollback after signaling advertised the feature returns 404. Signaling maps
    that to a retryable outcome, and the agent keeps the report.
- **Activation order:** control plane, then signaling, then agent. Each step is harmless alone.

### 3. Authority (medium)

The safety claim is limited to **correctly behaving agents**:
- An authenticated device end report is a trusted lifecycle assertion for that device's own rows
  in its own tenant. It is the same authority `guest-ended` already grants: the guest-ended route
  already lets a device end any of its own open rows.
- v3 adds no privilege beyond that existing route. It adds a reason field and more callers.
- A compromised agent could close its own rows while streaming and free cap slots. The cap is
  therefore not a control against a compromised agent, which already controls the machine and its
  sessions. This is documented as such, not claimed otherwise.
- Tests:
  - forged `device_id` / `tenant_id`;
  - a bad service token;
  - a same-tenant cross-device id, which returns `other_device`;
  - signaling ignoring any device or tenant in the message.

### 4. Shutdown, queue loss and the meaning of ended_at (medium)

- **Shutdown drain.** On a service stop, the agent queues `service_stop` reports for live sessions
  and gives the report worker a bounded drain, up to 5 s while signaling is connected, before
  exiting.
- **Losses are measured, not assumed.** Undelivered reports at exit, queue overflow evictions and
  retry outcomes are logged with counts.
- **No persistence in v3.** It is a follow-up if measurement shows shutdown and crash loss matter.
- **`ended_at` for an agent-reported end is CLOSURE-OBSERVED time,** when the control plane learned
  of it, not the true end of the transport.
  - The audit event records `reason`, `observed_by: agent_report`, and the report's queue age as
    the agent measured it, so reports and the console can label the duration "approximate" for
    these rows.
  - Retry delay is unbounded while a machine is offline, and that is stated.

### 5. Existing leaked rows (medium)

- **Device re-registration is NOT proof** that an old session is gone. It is withdrawn.
- Existing leaked rows stay outside v3. Cleaning them up needs either an operator action that
  terminates the affected sessions, or a separately reviewed fencing mechanism.
- Until then an operator can end them through the existing `/end`, row by row.

### Measurement (revised)

- **Per new session,** captured at start: the agent version (from the presence or registration
  inventory at start time, stored in the audit start event), mode (control or observer), and the
  terminal outcome after a full 24 h window (`/end`, agent report and reason, reaper, still open).
- **Plus** queue age, depth, evictions and shutdown-undelivered counts from agent logs.
- **The ~27% reduction is a hypothesis** to measure on updated-agent cohorts.

### Additional end-to-end tests

- observer teardown;
- two simultaneous sessions on one agent, where ending one leaves the other's row open;
- a signaling reconnect with live WebRTC, which sends no report;
- a delayed report after a viewer reconnect, which ends only the old row;
- a temporary control-plane or signaling outage, where the report is retained and later delivered;
- queue overflow;
- graceful service stop.

## Non-reuse and shutdown contracts

### Non-reuse of a session id is a code fact, enforced by a guard (high)

- **A `session_record` id receives exactly ONE ticket, ever.**
  - `MintSessionTicket` and `MintObserverSessionTicket` are called for a `session_record` only in
    `handleStartSession` (`http.go`), for `rec.ID`: the row created in that same request, with
    the fixed deadline `now + sessionTicketTTL` (2 min).
  - No route re-issues, renews or extends a ticket for an existing session id.
  - The single-use ledger row for that ticket lives until `expires_at + 1 h`. That outlives the
    only ticket the id will ever have, so no second redemption, and no second agent lifetime, can
    occur for that id across processes, restarts or replicas.
- **The only other caller,** `http_attended.go`, mints for an ATTENDED session id, which never has
  a `session_record` row. The agent sends NO end report for attended sessions; that path already
  uses `guest-ended` semantics. A stray report for an attended id would return `not_found` and
  change nothing.
- **Enforced, not just observed.** A new AST guard test, in the style of
  `TestServerPackageCannotSign`, fails the build if `MintSessionTicket` or
  `MintObserverSessionTicket` is called anywhere except those two sites. A future "re-issue ticket
  for reconnect" feature therefore has to revisit this design.
- **The agent's bounded "ended in this process" fence stays** as defence in depth, not as the
  invariant.
- **Tests:**
  - the guard test;
  - a second start never reuses an id;
  - a redemption after ledger expiry is impossible because the ticket's signed deadline has
    already passed (existing ticket-expiry checks);
  - an agent restart while a report is queued: the report is in memory and is lost, the row stays
    open, and nothing is wrongly closed.

### Capability detection (medium)

- **An explicit, authenticated capability endpoint** replaces the nil-UUID probe:
  `GET /internal/capabilities` (the same service-token auth as the other internal routes) returns
  `{"features":["session_ended_v1"]}`.
  - **404:** route absent, an older control plane; do not advertise.
  - **401/403:** misconfiguration OR an older control plane; do not advertise, log loudly, retry.
    Measured in the CP slice: an internal route that is not mounted falls through to the
    session-authenticated chain and answers **401, not 404**, so 401 is the usual "route absent"
    answer for both this probe and `/ended`.
  - **5xx or network errors:** transient; do not advertise yet, retry.
- **Signaling refreshes the probe** every 5 minutes and advertises the feature to agents that
  register after a positive probe.
- **Mixed or rolled-back control-plane replicas:** a request-time 404 WITHOUT the store's
  `session not found` error, and any 401, on `/ended` is mapped to a RETRYABLE outcome, so the
  agent keeps the report and retries. Only the handler's own `session not found` 404 is terminal. A missing route on one replica
  never terminates a report.
- **Tests:**
  - supported, with an `/ended` not-found session, returns the terminal `not_found`;
  - a missing route is retryable;
  - auth errors;
  - transient errors;
  - the probe refresh flipping the advertised feature.

### Shutdown ordering (note)

Service-stop reports are queued only after each session loop has torn down and joined its media
and input tasks. The 5-second drain starts after the last report is queued.

**Implementation limit, found in the 1.3.6 release review (2026-10-20).** The drain runs when the
helper's own `stop` flag is set (the stop-file path) or an uninstall is requested. The Windows
**service STOP does not do that.** `service.rs` `teardown_core` calls `TerminateProcess` on every
helper and then waits `TEARDOWN_WAIT` (10 s) for them to exit.
- A session that is open while the SERVICE stops (a reboot, a manual `sc stop`, an MSI that stops
  the service) is therefore not reported, and its row stays open exactly as before docs/49.
- This is not a regression. The update path already waits for idle (the session idle barrier), so
  the realistic case is a reboot during a session.
- **Follow-up:** a graceful helper stop. The service would signal the helper, for example with a
  named event (not the shared stop file, which outlives a crash), and wait about 15 s inside the
  SCM stop-pending hint before terminating. That is a service-lifecycle change and needs its own
  review.

**Graceful stop, BUILT (4359292 + 5ede5c9, 2026-10-20; ships in the next agent release).**
- **How it works:**
  - The service sets a per-start named event (`crate::helper_stop`) on STOP/SHUTDOWN/PRESHUTDOWN;
  - it waits up to 18 s (the helper's join and drain budget + 3 s), and only then terminates helpers still running;
  - it now accepts PRESHUTDOWN and sets a 40 s preshutdown timeout.
- **Stop-Service validation:** a live CP-vouched session reported `service_stop` and ended;
  the 1.3.6 negative control reported nothing.
- **A reboot or sign-out with a session open: covered by the helper itself.** The user session's logoff kills the session-1 helper about 0.6 s into a restart, about 20 s before the SCM sends PRESHUTDOWN, so the service alone cannot cover it (measured).
  - **How:** the helper keeps a hidden top-level window. On WM_ENDSESSION it requests the same stop and holds the message for up to 4 s while the drain runs (`helper_stop::arm_session_end`).
  - **VM-proven** (final build, phases F/G/H): `Stop-Service`, `Restart-Computer` and a sign-out each reported a live session `service_stop` and ended its row. The drain takes 0.13-0.5 s. After a sign-out the login-screen helper re-registers.
  - **Not used:** console control events, because CTRL_LOGOFF_EVENT can reach a SYSTEM console process on another user's sign-out.
  - **Still open:** the liveness sweep respawns helpers into a session being logged off (behaviour that predates this change; each respawned helper now exits after an empty drain).
