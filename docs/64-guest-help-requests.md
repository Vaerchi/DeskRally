# docs/64 — Guest-initiated help requests from enrolled machines (design)

This design adds guest-initiated help requests from enrolled machines, without requiring
a technician to mint an attended-session code first.

## 1. What the map established

- Attended sessions are technician-minted only (`POST /attended-sessions`, single-use code). Seven public guest
  routes exist; none creates work for a technician.
- The installed agent's tray icon has an empty menu (`tray.rs`: the callback goes to `DefWindowProcW`); the
  presence pill and guest chat exist only during a live session.
- An enrolled agent holds an AUTHENTICATED signaling socket (`RMTAGENTAUTHv1`); `session_ended` is the
  precedent for an agent-originated event that signaling forwards to the control plane with the identity it
  already verified (`sessionended.go` → `/internal/sessions/{id}/ended`, device-token authorized).
- The bell polls tenant-wide `GET /audit` (`CapViewAudit`, no group filter); webhooks fire only from
  `recordMgmtAudit` / toolbox. No email, push or SSE exists.

## 2. Decisions

**D1 — Shape: "Request help" from an ENROLLED machine** (tray menu → authenticated socket → group-scoped queue).
Rejected: a public queue on the join page (an anonymous write that creates technician work; the existing
throttle meters failures only, so a form where every POST succeeds is never throttled; tenant discovery
surface; anonymous text reaching technicians is a social-engineering path); a guest-minted attended code
(inverts the trust of a code minted by an authorized principal); the tenant-wide audit bell as the queue
(leaks across group coverage). Unenrolled guests keep the technician invite flow.

**D2 — Agent.** The tray icon gets a right-click menu with **"Request help…"**, shown only while the agent is
registered with a server that advertises `help_request_v1` in `Registered.Features`. The menu requires genuine
hardware input (reuse `tray_menu_provenance.rs`; injected input — including a remote technician's — does not
open it). It opens a small native dialog with an optional note (≤ 200 chars) and Send / Cancel; after sending,
the tooltip reads "Help requested — a technician will connect" and the item becomes "Cancel help request".

**D3 — Wire.** New client message `help_request {note}` / `help_cancel {}`; identity (tenant, device) is taken
from the authenticated connection, never from the body. Signaling: registered peers only, per-peer rate limit
(e.g. 3/hour), forwarded through a bounded worker pool to `POST /internal/devices/{id}/help-request` (and
`/help-cancel`), authorized exactly like `guest_end.go` (device-identity token + tenant check). Unknown to old
servers → never sent (feature gate); unknown to old agents → nothing changes.

**D4 — Control plane.** Migration: `help_request (tenant_id, id, machine_id, group_id, note, status
open|accepted|cancelled|expired, created_at, expires_at, accepted_by, session_id)`, composite FKs, RLS, partial
unique index "one OPEN request per machine" (a second request while open is idempotent: refreshes nothing,
returns the existing one), expiry 30 minutes, per-tenant cap of open requests (e.g. 100). The group is resolved
from the STORED machine row, never from the request. Note: control characters stripped, length capped,
always rendered as plain text labelled "from the guest's machine". Audit rows `help.requested`,
`help.cancelled`, `help.accepted`, `help.expired` via `recordMgmtAudit` (so webhooks dispatch exactly once per
transition, behind the existing per-subscription event filter). A retired/quarantined machine's request is
refused.

**D5 — Technician side.** `GET /help-requests` lists open requests filtered per principal by
`AllowsInGroup(CapStartSession, machine.group)` (so docs/62 subgroup inheritance applies automatically);
`POST /help-requests/{id}/accept` is single-use and atomically marks the request accepted and returns the
machine for the normal unattended session start, which carries `help_request_id` into the session audit row.
A request from a machine that is now offline shows "offline" and no accept button. Console: a "Help
requests" badge + list (separate from the audit bell, polled with the existing cadence), and the two notable
actions added to the bell's map for tenant-wide auditors.

**D6 — Consent semantics.** Unattended sessions have no guest consent gate today; a help request does not add
one and does not remove any existing guard — it is recorded as context (who asked, when, the note) on the
session audit row. It is single-use and expires, so an old request cannot be replayed into a later session.

## 2a. Binding contracts — these supersede §2 where they differ

- **H-C1 Accept creates the session.** Accept is one transaction: recheck the request is open and unexpired,
  the actor's CURRENT coverage of the machine's CURRENT group (`AllowsInGroup(CapStartSession, …)`), and the
  machine's eligibility (active, online); create the session record bound to (request, tenant, machine,
  technician); mark the request accepted with that session id. The client then connects with the ticket for
  THAT session only; a request id can never be attached to another session. A start that fails after accept
  returns the request to `open` (if still unexpired) with an audit row; lost responses are retried with an
  idempotency key and return the same session.
- **H-C2 Durable abuse limits in the control plane** (not per signaling peer): per device ≤ 3 creations/hour
  and ≤ 10/day, per tenant ≤ 200/hour, tenant open-cap admission serialized under a tenant advisory lock,
  explicit 429 overload responses; signaling bounds frame size (note ≤ 200 chars, frame ≤ 1 KiB) and its
  worker queue (drop with a logged overload). Closed requests are pruned after 30 days.
- **H-C3 Request identity.** The agent sends `help_request {op_id, note}`; the server returns the request id
  (dedup on (device, op_id) for 24 h). `help_cancel {request_id}` cancels only that request, only for the
  authenticated device. Race rules: accept vs cancel vs expiry — the first committed transition wins, the rest
  get 409 with the current state.
- **H-C4 Agent state sync.** The tray shows "Sending…" until the server's ack (persisted), then "Help
  requested — waiting for a technician" (not "a technician will connect"); the agent re-queries its open
  request on every reconnect and on a 60 s timer while open, and resets the UI on accepted / cancelled /
  expired / refused.
- **H-C5 Authorization is always current.** Every list and mutation evaluates the machine's CURRENT group;
  the stored `group_id` is informational only. Retiring or quarantining the machine cancels its open request;
  moving it re-scopes visibility immediately (no cancel).
- **H-C6 Expiry and audit.** Expiry is applied lazily inside create/list/accept transactions (an expired
  `open` row is transitioned before counting) plus the 5-minute reaper; each transition commits its audit row
  in the same transaction (an outbox row drives webhook delivery with the existing retry/dedup semantics —
  at-least-once, never promised exactly-once).
- **H-C7 Local initiation.** The tray menu AND the dialog's Send accept only the guest's own input, never a technician's
  (provenance checked on the action, not just on opening; see "Input-dead dialog, 2026-11-04" below for what "own" means
  and why Cancel, Escape, typing and focus do not depend on provenance); the helper talks to the agent's signaling
  task over the existing helper↔service channel (no new listening surface). Attribution is labelled "requested
  from the machine" (an enrolled-device assertion relayed by signaling), never as proof of a person or of
  consent.

## 3. Stages and deploy order

H1 control plane (migration, internal route, store fake+pg, technician API, audit) + signaling (message,
feature advertisement, forwarder) — deployed first. H2 console (badge, list, accept). H3 agent (tray menu,
provenance, dialog, socket send) in the next agent release; the agent sends only when the feature is
advertised.

## 4. Tests

Control plane: authenticated device only; tenant isolation; one-open-per-machine idempotency; expiry; cap;
retired machine refused; group scoping with an asymmetric pair (covered technician sees and accepts, uncovered
sees nothing and gets 403/404 on accept); accept single-use under concurrency (two technicians race → one
wins); session audit carries the request id; webhook dispatched exactly once per transition; fake = pg.
Signaling: unregistered peer refused; identity from connection not body (a body naming another device is
ignored); rate limit; feature advertisement. Agent: injected input cannot open the menu (with a real-input
positive control); menu absent until registered with the feature; VM: a real right-click → request appears in
the console → accept → session. Console e2e: in-scope only, accept starts the session.

## 5. H3 as built (agent, 2026-11-02)

Product rules decided for this stage: help requests come from the TRAY of an ENROLLED machine only (never the public join
page), and a RETIRED machine may not send them. Files: `crates/protocol/src/signaling.rs` (wire), `crates/agent-windows/src/`
`help_request.rs` (state machine + tray decision logic, all platform-neutral), `help_request_tests.rs`, `help_dialog.rs`
(the note window), `tray.rs` (menu, tooltip), `signaling_mux.rs` (routing), `host.rs` (wiring), `tray_menu_provenance.rs`.

**Where it runs.** The user-session helper owns BOTH the tray icon and the authenticated signaling connection, so the request
goes tray thread -> `HelpHub` (one per helper lifetime, across reconnects) -> the mux's `SignalingClient`. There is no
service hop and no new listening surface (H-C7). The mux attaches the live connection to the hub as its sink on every
registration and tags answers with that connection's generation, so an answer from a dead connection can never settle the
new one (the same scheme as the directive hub).

**Wire (matches `server/signaling/messages.go` exactly).** Client: `help_request {op_id, note?}` (note omitted when empty),
`help_cancel {request_id}`, `help_status {}`. Server: `help_request_result {op, op_id?, outcome, request?, retry_after_seconds?}`
with `request = {id, status, note, created_at, expires_at}`. Outcomes are strings (`ok`, `conflict`, `refused`, `limited`,
`not_found`, `unavailable`) so a newer server's value cannot fail the decode. The feature constant is `HELP_REQUEST_FEATURE =
"help_request_v1"`; pinned by `help_messages_have_the_exact_go_wire_shape`.

**Feature gate and "retired may not request".** The hub is told, per connection, whether `Registered.features` listed
`help_request_v1`. Signaling never lists it for a restricted (retired) connection nor for a control plane without the routes
(`registeredMsg`), so "retired", "old server" and "offline" are all just "feature absent": the menu is not shown at all, and
nothing help-related is ever put on the wire. That matters beyond tidiness: a restricted connection answers an unknown message
with `Rejected`, which ends the mux. A reconnect that loses the feature (machine retired meanwhile) hides the menu and stops
the timers.

**§2a contracts.**
- H-C2 (client half): at most 3 creations/hour and 10/day (counted when the server acks a creation), 12 messages/minute (the
  signaling window), and a `limited` answer blocks new requests for `retry_after_seconds` (capped at 24 h). The note is
  <= 200 characters (the EDIT enforces it; `sanitize_note` also strips control, bidi and format characters and caps it), which
  keeps the frame far under signaling's 1 KiB bound. The server stays the authority.
- H-C3: every request carries a fresh `op_id` (UUID, 32 hex); an unacknowledged request is re-sent with the SAME `op_id`
  (every 20 s, uncertain after 120 s (see below), and re-sent on reconnect); an answer naming another `op_id`, or
  none, settles nothing. `help_cancel` names the request id, and is offered only for an acknowledged open request. A cancel that
  loses a race returns `conflict` with the winning state, which the UI shows (e.g. accepted).
- H-C4: the tray shows "Sending your help request..." until the ack, then "Help requested - waiting for a technician" (never
  "a technician will connect"). The hub sends `help_status` on every (re)attach (this also surfaces a request opened before the
  helper restarted) and every 60 s while open, and resets the UI on accepted / cancelled / expired / refused. A status
  that returns the device's LATEST closed request while nothing is open is not news (no stale notice).
- H-C7: both the menu choice AND the dialog's Send are accepted only when the guest's own hardware input made them. The menu
  runs under `tray_menu_provenance::watch`. The dialog's pump drops this product's injected keyboard/mouse input before
  `IsDialogMessageW` (the `code_prompt` rule), and Send is authenticated AT THE ACTION : a `WM_COMMAND` can
  be posted by any same-integrity process, so the dialog's own low-level hooks feed a `SendAuth` and the command is honoured
  only for a COMPLETE genuine gesture on the Send button: a left-button DOWN on Send then the left-button UP still over Send, or Space DOWN then its UP while Send has the focus, or Enter DOWN while Send has the focus, accepted only synchronously inside the dispatch of the one `WM_KEYDOWN(VK_RETURN)` whose `MSG.time` and scan code equal the hook event's (a forged Enter queued ahead neither consumes nor authorizes), and only if Windows reports the message as input-queue input (`GetCurrentInputMessageSource`: `IMO_HARDWARE`, `IMO_INJECTED` or `IMO_SYSTEM`, fail closed); Space and left-button releases to Send that are not input-queue input cannot authorize Send (they are still delivered; see the 2026-11-04 entry below) (the dialog manager sends the default-button command on the DOWN itself); there is no time window for Enter, so a forged `WM_COMMAND` can never consume it (single-use, 2 s). Any other genuine input in between clears it (a press elsewhere, so a drag onto Send never starts one; another mouse button; another key). Space typed in the note box, a posted `WM_COMMAND`/`BM_CLICK`, or Enter in the note box does not send; this product's own tagged input (a technician's) taints the dialog for its lifetime, an injection by a lower-integrity process voids the gesture it interrupts, and untagged injected input at the helper's integrity or above (a guest's remapper) counts as the guest's (see the 2026-11-04 entry below); if the hooks cannot be installed the dialog
  is not shown. The shared `tray_menu_provenance` is unchanged.
- **Dialog focus and input constraints (agent 1.3.19).** Testing a SYSTEM dialog in the interactive session found two independent causes of
  lost text input and incomplete button clicks:
  1. **Focus.** `DefWindowProc` answers a `WM_ACTIVATE` by focusing the top-level frame. Any deactivate/activate cycle (a click on the desktop, the
     tray menu closing, an overlay taking and returning the foreground) left the note box without the focus: `WM_CHAR` went to the frame and was
     dropped, while `IsDialogMessage` still turned Escape into Cancel. Fix: the frame handles `WM_ACTIVATE` / `WM_SETFOCUS` and returns the focus
     to the last focused child (the note box at first), remembered on every pump turn, and focuses the note box after it is shown. The dialog
     asks for the foreground with `SetForegroundWindow` only; when Windows refuses (the tray's foreground right already spent) the taskbar
     flashes and the topmost dialog waits for the guest's click, which activates it and restores the focus. There is deliberately no
     `AttachThreadInput` fallback: attaching to an arbitrary foreground thread lets a hung application hang the helper before its message
     loop runs .
  2. **Provenance on Cancel.** The pump dropped EVERY `WM_LBUTTONUP` (and Space-up) whose `GetCurrentInputMessageSource` was not `IMO_HARDWARE`,
     whichever control it was for. Software that re-injects the guest's own mouse (a SYSTEM-level mouse remapping service; also KVMs, Parsec, Steam
     Link, on-screen keyboards) reports `IMO_INJECTED` for every click (VM: origin=2 for a SYSTEM `SendInput`), so the press reached the button
     and the release never did: no button could complete a click, Cancel included. The low-level hooks additionally tainted the whole dialog on ANY
     event carrying the OS injected flag.
  **Decision (written down, not implied).** Only SEND is authenticated; Cancel, Escape, the close box, typing in the note and focus changes never
  depend on provenance (a technician cancelling or typing in a dialog the guest opened is harmless: the guest still has to press Send). For Send:
  * REFUSED, always: the product's own injection (`dwExtraInfo == RMT_INJECTED_TAG`, a technician's session; these are also dropped by the pump
    before the dialog manager, as before), which taints the dialog for its lifetime. An injection by a lower-integrity process
    (`LLMHF/LLKHF_LOWER_IL_INJECTED`) never counts toward a gesture and voids the one it interrupts (press, Space or Enter in progress, or a
    completed gesture awaiting its command), but does NOT taint: the flag names the injector's integrity, not a technician, and a guest's own
    lower-integrity remapper or accessibility tool raises it anywhere on the desktop, which used to disable Send for the dialog's whole life
    . The guest's next genuine gesture sends. Posted or sent look-alikes (`WM_COMMAND`, `BM_CLICK`, `WM_LBUTTONUP`, `WM_KEYUP(VK_SPACE)`, `WM_KEYDOWN(VK_RETURN)`) report
    `IMO_UNAVAILABLE`: a release addressed to Send is still DELIVERED (a button that never sees its release keeps the mouse capture, looks
    pressed and swallows every later click: the observed 1.3.19 symptoms), but the Send command produced while it is dispatched is refused, and any completed
    gesture is voided first (a posted release dequeued ahead of the guest's real one takes its place, and the record must not stay usable by a
    forged command for the 2 s freshness window; the guest sees the hint and clicks again). No release is ever dropped by provenance.
  * **Bound to the release dispatch.** A message SENT straight to the window procedure never passes through the message
    loop, so the loop's checks cannot see it. A mouse/Space gesture therefore authorizes Send only synchronously inside the loop's dispatch of a
    VOUCHED release to Send (single-use flag, like Enter's); every Send-bound release dispatch voids the record afterwards, so a gesture whose
    release produced no click (a sent `WM_LBUTTONUP` let the button go first) leaves nothing for a later forged `WM_COMMAND` / `BM_CLICK`.
    (Posting or sending to this SYSTEM-integrity window also needs a SYSTEM-integrity sender: UIPI blocks lower ones.)
  * ACCEPTED: a complete gesture (press and release over Send, or Enter / Space with Send focused) whose hook events and messages are real input
    queue input, i.e. `IMO_HARDWARE` OR `IMO_INJECTED` that does not carry this product's tag, or `IMO_SYSTEM` (generated by Windows itself;
    a posted look-alike reports `IMO_UNAVAILABLE`, never this, and refusing it could only lock out an input path the lab cannot reproduce). A guest whose mouse goes through remapping software
    must be able to click Send.
  * **Residual risk, accepted.** The tag is not a security boundary (any process can set `dwExtraInfo`; `input.rs` says so). A hostile process that
    already runs on the guest's desktop at equal or higher integrity can synthesize an untagged click on Send. The consequence is one help request
    (rate-limited 3/hour, 10/day, attributed "requested from the machine", never consent) from a machine on which that process can already run code
    as the user or SYSTEM, including a technician's command-run, which is audited on its own. The technician's own remote-input path always tags
    and stays refused. A lower-integrity injector cannot reach this SYSTEM-integrity dialog at all (UIPI; VM: nothing arrives), which is also why
    a remapper that injects at USER level cannot work on this dialog whatever the code does (open point: lowering the dialog's integrity).
  * **Enter on a focused Send.** The hint tells the guest to select Send and press Enter, so it has to work: the Enter record is no longer cleared
    by Enter's own key release (a quick press delivers both low-level hook events before the message loop dequeues the DOWN, so it failed about
    half the time in the VM). It stays single-use, tied to the DOWN's time and scan code, vetted by the input-queue origin and 2 s fresh.
  * **The dialog explains itself.** A refused Send changes the text under the note box to "Send was not accepted. Click Send again, or select it
    and press Enter. ..." instead of silently doing nothing.
  * **Touch and pen.** The origin check looks at `originId` only (`IMO_HARDWARE`, `IMO_INJECTED` or `IMO_SYSTEM` passes), never at `deviceType`, so a touch or pen
    gesture (promoted to mouse messages by the OS) is not refused for its device type; the hooks taint only on this product's tag and void a
    gesture only on a lower-integrity flag, neither of which touch sets. Not testable in the Hyper-V lab (no touch device); covered by `origin_is_real_input` and the
    taint-rule unit tests only. If a touch device reports an origin other than these three it is refused fail-closed and the hint appears.
  * **No stated origin, bound to the hook (1.3.22).** On a physical Windows system running 1.3.21 `GetCurrentInputMessageSource` answered
    `IMO_UNAVAILABLE` / `IMDT_UNAVAILABLE` for every GENUINE left-button release on Send. Every other gate passed (press began on Send, release
    over Send, hit window = Send, no taints, foreground, focus). The cause is not established; the lab reports `IMO_HARDWARE`. On that machine the
    origin cannot tell the guest's real click from a posted look-alike, so the strict rule left Send unusable with the mouse.
    **Decision.** `IMO_UNAVAILABLE` is its own class, neither accepted nor refused by itself:
    - A Send-bound release with that origin is vouched only when bound to the low-level hook's record of the release that COMPLETED a genuine
      gesture on Send. The binding is `MSG.time` at, or at most 250 ms after, the hook's `MSLLHOOKSTRUCT` / `KBDLLHOOKSTRUCT` time stamp
      (modulo the tick wrap; a layer that re-posts the release stamps the post time), single use, and cleared with the gesture.
    - Enter admits it after its existing time stamp and scan code match.
    - Unknown origins and failed queries stay refused.
    **Accepted consequence.** A look-alike posted by a sender that UIPI lets
    reach this SYSTEM-integrity window can stand in for the guest's own completed gesture, or for their recorded Enter DOWN, within that window.
    Such a sender is another SYSTEM-integrity process in the session, or a uiAccess process. It cannot create a Send the guest did not just
    make: every path still needs the hook's genuine, untainted, fresh gesture on Send, and the command is still accepted only inside the
    vouched dispatch. A sender at that integrity can already act as SYSTEM (see the residual risk above), so this adds no capability.
    Refusing instead would lock out every guest whose machine reports no origin, so the requirement "a posted look-alike never sends" is
    narrowed to "a posted look-alike never sends a gesture the guest did not make".
    The closing line counts `unavailable_admitted=` and `max_bind_delta_ms=`, and a refused release logs `msg_time=` and `hook_release_time=`,
    so a canary run shows the real gap.
  * **A refusal is never silent.** The hint is shown from both refusal paths: the refused `WM_COMMAND` and a Send-bound release the pump could not vouch for.
  Tests: `help_request_tests.rs` (unvouched-release rule per target and source, hook-event classification, remapped-versus-tagged gesture,
  lower-integrity void-and-recover), `help_dialog.rs`
  (`origin_is_real_input`, `focus_target`); VM acceptance is `scripts/vmlab/help-dialog-lab.ps1` (hardware, third-party, tagged and posted
  scenarios against the real dialog as SYSTEM in session 1; `agent_host help-dialog-probe`, test-harness builds only).
- Cancel (review 2): `cancel(expected_id)` names the request the menu showed and sends nothing if the current request differs.
  Answers are correlated by the request id the server echoes; an answer about another request touches nothing. A cancel
  `not_found` carries no request id and a cancel has no `op_id` (`helprequest.go` passes ""), so it cannot be attributed: it
  settles nothing and only triggers a `help_status`. Signaling now echoes `cancel_of` (the request id) on EVERY `help_cancel` answer, `not_found` included (protocol: `cancel_of`, optional); with it every cancel answer is correlated by id (a `not_found` about the current request settles it as cancelled, one about another request is ignored). Against an older signaling without `cancel_of` the fallback above applies.
- Uncertain sends (review 3): with no answer for 2 min the request is UNCERTAIN, not failed: the op_id is kept and replayed
  every 60 s (the server dedups on it for 24 h, so the answer is authoritative: the original request, or it is created now),
  the tray says "Checking that your help request was received...", and no new request or cancel is possible until an
  authoritative answer arrives (a late ack, an open request found by `help_status`, a refusal, a limit, or a reconnect that
  loses the feature). Replays stop 20 h after the FIRST send (the server dedups an op_id for 24 h, and a replay would create a second request after that): from then on only `help_status` is asked, and a status with no open request ends the uncertainty (any request made has long closed) without claiming failure.- D6 wording: the dialog says "This sends a request to your support team from this computer. A technician may then connect to
  it." No consent gate is implied or added.

**Tray UX.** Right-click: a greyed status line, then "Request help..." (greyed while sending or limited) or "Cancel help
request". The tooltip follows the state (`DeskRally - Ready for support - Help requested - ...`); the hub posts a message to
the tray window on every visible change. A click during the menu or dialog cannot open a second one.

**Tests (no OS-visible call).** All decisions sit behind the `HelpUi` trait; tests use a recording double, a recording sink,
and a clock they move. Covered: feature absent -> no menu, no send; request/ack/open/cancel; accepted/expired/cancelled via
the status poll and via a lost cancel race; stale generation and wrong `op_id` ignored; resend/give-up; reconnect resend and
re-query; the three limits; `limited` blocking; injected menu choice / injected Send / injected cancel all ignored with a
real-input positive control; the dialog not offered while open or limited; and, over a real loopback socket, the mux carries
a request frame and routes an answer into the hub, while a connection without the feature emits no frame at all. The Win32
menu and dialog (`tray.rs`, `help_dialog.rs`) compile but are NOT exercised by any test.

**Not done / to verify.** (1) VM acceptance: a real right-click -> dialog -> request in the console -> accept -> session, and
that an injected right-click or Send (a technician) does nothing. (2) The dialog's layout and DPI were not looked at. (3)
No balloon notification on accepted/expired; the status line and tooltip carry it. (4) The in-memory client limiter resets
when the helper restarts; the control plane's durable limits cover that. (5) Ships in the next agent release; the agent sends
only when the feature is advertised, so it is inert against a server without H1.

**Also in this branch (security audit 2026-11-01 #8).** `signaling_mux.rs`'s pre-`Brokered` buffer is now bounded: <= 64
sessions, 32 messages and 256 KiB per session, 1 MiB in total, entries older than 30 s forgotten. A session that blows its own
budget is discarded and poisoned (a `Brokered` for it is refused and reported), a full table drops the newcomer, and drops are
logged once, then every 1024th.
