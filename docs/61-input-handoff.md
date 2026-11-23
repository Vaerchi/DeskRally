# docs/61 — Handing input control between technicians inside one session (design)

Concurrent sessions on one machine ship and are e2e-proven
(`multi_tech_shared_control.spec.ts`: independent tickets, independent VP8, shared-key refcounts);
the missing piece is "handing control between technicians inside one session". Mapped 2026-10-30 by
three read-only surveys (agent input path; viewer/e2e; CP session semantics) before designing.

## 1. What the maps established

- The agent has NO input arbitration: sessions interleave freely where they meet — the machine-wide
  SharedCapture drain → `InputCoordinator` (per-key/button refcounts) → the single `SendInputSink`
  (one typist thread, one cancel generation). The coordinator is the only object that sees all
  sessions; each session task is otherwise isolated.
- The one lever that already blocks one session's input is per-session ADMISSION (GatedSink +
  shared `Admission`, both epoch-fenced; releases ALWAYS pass; `set_input_admitted` cancels typing
  around the flip). Its gaps: reachable only from a session's own loop, and no registry maps
  session → Admission for cross-session action.
- `view_only` is a ONE-WAY RATCHET with floors (observer, provisional, signed policy, toggle,
  indicator-lost) and is a security property. It must not be mutated by arbitration.
- The CP's authority model is per-session and immutable (ticket, technician, access, audit chain
  bound at brokering); docs/51 transfer is a full hand-OFF (end S1, start S2) and explicitly excludes
  in-session control passing. A renewal can only demote. Observers can never be promoted.
- Viewer rules: adopt only the AGENT's ack (ViewOnlyApplied pattern); no new buttons in the session
  top-bar row; the participant list keys on SIGNALING ids and carries no "holds control" bit; minimal
  chrome hides the row, so prompts must be in-page.

## 2. Semantics (the load-bearing decisions)

**D1 — The arbiter is the agent's coordinator; ownership is RUNTIME state, not policy.** A new
machine-wide `input_owner: Option<SessionHandle>` lives beside the coordinator, with a registry
`session handle → (Admission, technician_id, name)` populated at session registration. The CP and
viewer are reporters, never enforcers.

**D2 — Opt-in compatibility mode, STICKY once armed (review r1).** With no hand-off ever invoked,
behavior is exactly today's (free interleave, refcounted keys) — the four pinned Phase-1 e2e behaviors
stay green. Unowned is a visible MODE, not exclusivity. Once arbitration is armed by the first hand,
ownership is sticky: the owning session's teardown moves to an explicit NO-OWNER, INPUT-BLOCKED state
(announced to every participant), never a silent fall back to free interleave — an exclusivity
indicator must not be able to lie. Every participant, including a session that joins later, receives an
authoritative mode/owner snapshot and ordered updates; notifying only the two parties to a hand is not
enough.

**D3 — An explicit state machine under the coordinator lock (review r1, the core repair).**
States: `Unowned(epoch)` → `Transitioning { id, from, to, epoch }` → `Owned { handle, incarnation,
epoch }`. `HandInputControl { to_session }` is honored only when the sender currently owns input, or
input is Unowned (the sender claims and hands in one serialized decision). Validation happens BEFORE
any state change: sender and target both LIVE and registered, target control-eligible (never an
observer), self-hand rejected without side effects; an invalid target must never leave the sender
owning as a side effect. Handles carry an incarnation id so a reused counter can never alias a dead
session. Concurrent hands serialize on the lock: the first valid transition wins and later requests
are judged against the resulting owner (the recipient may legitimately hand onward). `Transitioning`
admits NO new presses from anyone. The blocking cleanup runs OFF the lock; the transition commits only
if the transition id still matches and the target is still live — cleanup failure RETAINS
Transitioning and retries rather than announcing success; if the target disappeared, the resolution is
the explicit no-owner-blocked state, never a silent owner. **Entering arbitration from Unowned fences
and drains EVERY participant** — all sessions' held keys/buttons and queued/active typing — not
merely the sender's: in Unowned there is no single previous owner to revoke (review r1 H1/H4-answer-7,
the most-likely-wrong assumption, corrected). The owning session's clean end and a detected crash take
the SAME teardown path; an undetected viewer crash leaves ownership held until transport timeout, which
the design accepts and states. `release_session`'s tombstone is PERMANENT and is therefore never used
for temporary revocation — the owner gate is its own mechanism.

**D4 — Ownership gates INJECTION at the last gate before irreversible dispatch, epoch-stamped
(review r1 H2/H3).** Every non-release event — presses, Text, moves, wheel — is validated against the
ARBITRATION EPOCH at injection time, with the epoch stamped at enqueue: input queued during an earlier
ownership interval can never become effective later, including after the same session regains
ownership. Releases always reach coordinator BOOKKEEPING (holder-checked, epoch-aware) — a stale
release cannot release a new hold, and a non-holder's up cannot release the owner's key. The typist is
asynchronous, so Text acceptance is not enough: typist jobs carry their generation and owner, checked
at EXECUTION time, and a transition includes a COMPLETION BARRIER — the strict order is: close
admission and advance the epoch; stop stale producers; cancel and AWAIT active typing and queued jobs
(never holding the coordinator lock while waiting on a worker that may need it); finish key/button and
typing-release cleanup; only then commit ownership and open the recipient's gate. Every cancellation
source (set_input_admitted's double cancel, another session's teardown, release paths) obeys the same
ordering so none can cancel the NEW owner's typing. Characters already injected before the barrier are
accepted as history. Screen, clipboard-view, chat and file browsing of a non-owner are untouched.
**Coordinator-bypassing sinks** (attended/single-session paths, the elevated-input helper): v1 requires
PROVEN lifecycle exclusion — the multi-session service host never runs them concurrently with
arbitrated sessions — asserted in code and tests; if any can coexist, it must route through the
arbiter before this ships (review r1 H4).

**D5 — Audit records COMMITTED transitions, with enough to reconstruct who could type when (review
r1 A5).** `input_control_handed` carries the trusted session + incarnation ids, technician ids, the
transition id, the machine-wide epoch, the previous and resulting MODE, and is sealed into EACH
affected session's chain — and arming, teardown-to-blocked, and eligibility changes are events too,
because a hand alone cannot establish the full picture. A transition is never audited as successful
before its cleanup committed; a partial chain append has a durable retry, and the event stream states
what each chain can and cannot prove (integrity and order per chain; not atomic cross-chain agreement,
not OS-level injection success).

**D6 — Acks, never inference.** The agent answers the handing session AND notifies the receiving
session with `InputControlChanged { owner_session, owner_name }` on their Control channels; each
viewer renders ONLY that acked state (banner/badge in-page + Session menu state; nothing added to the
top-bar row). Observers never see a hand-control affordance (`allowControl` rule already exists).

**D7 — Mixed fleets: AFFIRMATIVE capability, correlated acks, snapshots (review r1 A6).** The viewer
offers the action only on an agent's affirmative capability advertisement — a timeout is unknown, not
capability — and every hand carries a request id correlated in the ack; state updates carry ordered
epochs and a full snapshot is sent on reconnect. An old agent silently ignoring the message results in
the viewer still showing SHARED input (it never displays a successful hand without the ack). The
old-viewer-on-new-agent case is defined too: such a viewer can RECEIVE ownership (it just types as
before) but never initiates or renders arbitration; the agent's snapshot message is additive and
dropped harmlessly by its codec. New messages join the exhaustive `observer_rule` match
(compile-enforced), the TS codec, and the golden vectors on BOTH sides.

## 3. Scope

IN: the coordinator owner model + registry; three Control messages (hand / changed / refusal via the
existing Error); viewer Session-menu action + in-page state; audit events; version gating; tests.
OUT (v2+): request-control consent flow; unilateral admin take; observer promotion (CP boundary);
cross-session chat; any CP schema change (none needed — v1 is agent-arbitrated with audit only).

## 4. Tests

- Rust unit (coordinator): claim/hand/refuse semantics under the lock; revoke releases held keys and
  buttons and cancels typing BEFORE the new admit; unowned teardown; releases pass while gated;
  single-session mode always-owner equivalence.
- Rust e2e (synthetic, gate-runnable): extend the multi-session harness — A types, hand to B, agent
  log proves A's subsequent presses are dropped at the coordinator while B's inject; key held by A at
  hand time is released by the revoke (no stranded Shift).
- Playwright `multi_tech_shared_control.spec.ts` phase 3: two harness pages, `HandInputControl` from
  A, assert `InputControlChanged` acks on both and injection attribution flips in the agent log. The
  four existing Phase-1 behaviors must stay green UNChanged (opt-in proof).
- Viewer: vitest for the codec + state adoption; a mocked-fixture UI spec (participants frame +
  control acks) for the menu action, the in-page banner, and the observer-never-offered rule.
- VM (class-B caveat, release acceptance): real keyboard hand-off between two consoles, stranded-key
  check on a real app — the synthetic layer cannot prove OS-level key release ordering.

## 4a. Input arbitration constraints

H1 all-participant fence on leaving Unowned (D3); H2 arbitration epochs validated at injection with
epoch-aware release accounting (D4); H3 typist execution-time generation checks + completion barrier
with every cancellation source ordered (D4); H4 bypassing sinks need proven lifecycle exclusion or
routing through the arbiter (D4). Also folded: the explicit state machine with Transitioning and
incarnation ids, sticky ownership with no-owner-blocked teardown and participant snapshots (D2), audit
of committed transitions only with transition ids/epochs/mode (D5), affirmative capability + request
correlation + reconnect snapshots and the old-viewer policy (D7).

## 5. Risks folded from the maps

The typist is machine-wide with one cancel generation (sequence revoke-then-admit); the recording
test sink logs only keys/buttons (extend it or scope assertions to keys); `session_slots` has no
Admission registry yet (new, under the coordinator lock); the harness carries no participant UI (UI
tests live in the mocked fixture, not the transport harness); e2e specs must spread PINNED or opt
out; never edit sources while a gate run is live; CRLF-safe edits only.

## 6. Stage-2 implementation notes

- `cancel_typing(true)` IS the completion barrier: its return guarantees no cancelled press can
  follow, and it then releases what typing still held; jobs enqueued AFTER the bump (the new owner's
  text) are unaffected by that cancel. Known accepted residual (pre-existing, documented in input.rs):
  a LATER cancellation from another source (e.g. a third session's teardown calling release_held)
  still cancels machine-wide typing — the safe direction; arbitration does not change it.
- The fence runs on a BLOCKING host task (the set_input_admitted precedent), never on the capture
  thread: the epoch bump at begin_hand already invalidates queued events wherever they drain, so
  capture-thread ordering is not needed, and cancel_typing(true)'s worst-case 5 s stall must not
  freeze every session's video.
- Identity/order carriers: `SessionInputEvent` gains `session_id` + `arb_epoch` (+ incarnation),
  stamped in `SessionInputSender::send` from an `Arc<AtomicU64>` mirror; the drain's inject arm gets
  the arbiter verdict AFTER the existing cancelled/admission/topology/selection filters, with
  `is_release_event` exempt exactly like the admission filter.
- The arbiter hub holds `Mutex<(InputArbiter, Registry)>` + an `RwLock` snapshot for the per-event
  verdict (correctness over atomics: a torn multi-atomic read could admit old-owner input across a
  transition). Registry entries: handle → incarnation, eligibility, technician identity, liveness;
  handles are process-monotonic (`next_session` fetch_add never reuses), incarnation kept anyway for
  wire-level safety when stage 3 maps control-plane session ids to members at message receipt.
- `coordinator.release_keys(handle)` can fail (OS refusal) and is retried bounded inside the fence;
  fence completion gates commit — cleanup failure retains Transitioning per D3.
- `release_session`'s tombstone stays reserved for real teardown; the arbiter's deny-at-drain is the
  only revocation mechanism for hand-offs.

## 6a. Concurrency constraints

The first integration build was reviewed and three defects were fixed (each with a mutation-killed
regression test; crate lib suite 921 green):

- **H1 (obsolete fence vs recovery owner).** A fence whose `release_keys` kept failing stayed
  deferred; if its target then tore down (→ `Blocked`) and another controller claimed, the stale
  fence would keep running `release_keys` against the NEW owner — cancelling its typing and freeing
  its fresh holds. Fix: the deferred-fence retry consults `transition_in_flight(id)` BEFORE any
  further cleanup and abandons a superseded fence (reporting its non-`Owned` outcome), so cleanup
  owed to one interval never runs against a later one. Test: persistent release failure + target
  teardown mid-fence + recovery reclaim, asserting the reclaimer's fresh hold survives.
- **H2 (stale same-session release across ownership regain).** Releases are exempt from the DENY
  gate so keys never strand, but coordinator holders key only on session handle — so a stale key-up
  from a session that regained ownership could free its NEW hold. Fix: a denied release is exempt
  ONLY for the CURRENT arbitration interval (`stamped_epoch == current`); a stale-interval up is
  dropped. It strands nothing because the transition fence already released every prior interval's
  physical holds. Test: ownership A→B→A, then a prior-epoch Shift-up must not free A's new Shift.
- **H3 (verdict/injection not atomic vs begin).** The per-event verdict dropped its snapshot read
  before injection, so an already-approved press/Text could be dispatched AFTER a hand's typist
  barrier. Fix: a `dispatch_gate` RwLock — the capture thread holds it for READ across verdict+inject,
  `begin_by_handle` holds it for WRITE across the `Transitioning` publish — so a hand can never
  interleave an in-flight approved dispatch; nothing approved under the old owner is pending when the
  host runs its barrier. The capture-thread `release_keys`' own `cancel_typing(true)` is a no-op
  (the host already drained the typist, and `Transitioning` admits no new typing), so it does not
  stall video. Test: a probe held under the gate proves `begin`'s publish blocks until dispatch ends.

Deferred to stage 3 (host integration): a host shutdown/cancellation policy for a hand whose fence
cannot complete (today the caller blocks until the capture thread resolves it or the agent stops →
`FenceAborted`); and marking a session retiring at `release_held` so a hand begun in the window
before its teardown sentinel drains resolves to `Blocked` sooner (today the epoch bump + sentinel
teardown already make it safe, just not instant).


## 7. Stage-3 design (wire protocol, host arm + audit, viewer) — from the stage-3 surface map

The stage-2 integration left `hand_input_control` reachable but with no production caller, no
session-id↔handle mapping, no identity/name in the arbiter registry, and isolated per-session audit
chains. Stage 3 adds the wire protocol, the host arm, audit, and the viewer. The map (2026-10-30)
confirmed CP needs NO change (v1 is agent-arbitrated with audit only).

**D8 — A machine-wide SESSION DIRECTORY on `SharedCapture` resolves the three gaps at once.**
`Arc<Mutex<HashMap<SessionId, SessionDirEntry>>>` keyed by the signaling session id (the uuid the
viewer names as `to_session`). `SessionDirEntry = { handle: u64, technician_id, display_name,
audit_chain: SharedAuditChain }`. Each session task inserts its entry at start (where `bs.session`,
the `SessionInputSender` handle, the technician, and the per-session audit chain are all in scope)
and removes it at teardown (beside `release_held`). The PURE arbiter registry stays minimal
(`incarnation`, `eligible`); names and audit chains are a host concern, not the state machine's.
Resolution: the handler maps `to_session` → entry → `handle`, then calls
`hand_input_control(my_handle, target_handle)`. Cross-chain audit and `owner_name` both read from the
directory. A departed target → `to_session` absent → `Error` (no hand begun).

**D9 — Three Control messages; the viewer renders only the agent's acked snapshot.**
- Inbound `HandInputControl { to_session: String }` (the target's signaling id; length-capped in
  `decode` like other ids). `observer_rule` → `Refuse` (observers never hand; the existing observer
  gate at the top of the control handler auto-rejects, satisfying D6).
- Outbound `InputControlChanged { owner_session: Option<String>, owner_name: Option<String>,
  mode: InputControlMode }` with `enum InputControlMode { Shared, Owned, Blocked }` — the FULL
  authoritative snapshot (D2/D7), not a two-party note. `owner_session`/`owner_name` are `None` for
  `Shared`/`Blocked`. Sent to EVERY live session on any mode change and to a session at
  join/reconnect. Classified agent→controller `Refuse`.
- Outbound `InputHandoffAvailable { available: bool }` advertised once at session start (the
  `AdminRightsAvailable` precedent): the affirmative capability that gates the viewer action (D7).
  An agent that never sends it → the viewer shows nothing (old-agent case). Classified `Refuse`.
- Refusals reuse `Error { message }` (D3/D6). Both sides get Rust (`control.rs`) + TS
  (`control.ts`) codec entries and byte-identical golden vectors.

**D10 — The hand runs on a BLOCKING host task; an arb-event channel broadcasts every mode change.**
The control handler is on the async loop; `hand_input_control` can stall seconds on the typist
barrier, so the handler `spawn_blocking`s it (the `set_input_admitted` precedent), then on the
returned `CommitOutcome` seals audit and broadcasts. Teardown-initiated `Blocked` originates on the
CAPTURE thread, which must stay non-blocking — so the hub publishes a mode-change event on a small
`mpsc` ("arb event": the new `(mode, owner)` snapshot), drained by a host task that broadcasts
`InputControlChanged` to every entry in the directory. Both the host-initiated commit path and the
capture-thread teardown path therefore converge on ONE broadcaster. Join/reconnect sends the current
snapshot to just the joining session (read from `arb.mode()` + directory).

**D11 — `input_control_handed` is sealed into BOTH affected chains; committed transitions only.**
`AuditAction::InputControlHanded { from_session, from_technician, to_session, to_technician,
transition_id, epoch, prev_mode, new_mode }` (the two exhaustive `AuditAction` matches —
`strip_nul` and the occurred-at/path extraction — are updated; no wildcard). On a committed hand the
handler seals it into the handing AND receiving sessions' chains (both from the directory); a partial
append retries durably and the stream documents it proves per-chain integrity/order, not cross-chain
atomicity (D5). v1 audits the committed hand and teardown-to-`Blocked`; arming and eligibility-change
events are a documented follow-up. A transition is never audited before `commit` returned `Owned`.

**D12 — Viewer: capability-gated Session-menu action + in-page banner, acked state only.**
A `lib/input_handoff.ts` model parallel to `admin_rights.ts`; `onInputHandoffAvailable` sets it. The
Session menu (never the top-bar row) offers "Hand input control to…" only when
`available && canElevate && !observing` (D7 affirmative capability; observers never offered — the
existing `!observing` rule). The action chooses a target from `session_participants` (the signaling
ids the agent will resolve) and calls `handInputControl(targetId)`. An in-page banner/badge renders
ONLY the acked `InputControlChanged` snapshot (the `ViewOnlyApplied` adoption pattern): owner name,
or "input shared" / "input locked". An old viewer ignores the message (`default: break`) and can
still RECEIVE ownership, never initiate/render (D7).

## 7a. Integration and validation sequence

Wire types and codecs require Rust and TypeScript golden vectors before host actuation
is enabled. Integrate the session directory, eligibility and broadcaster, then cross-chain
audit and durable retry, then viewer controls. Real two-console hand-off and a held-key
negative control are required: synthetic tests cannot prove OS key-release ordering.

## 7b. Stage 3b as built

- **D8 refined — the directory lives ON the arbiter hub**, not in `run_multi_session_stream`: that
  function is re-entered on every signaling reconnect with the SAME `SharedCapture`, and sessions
  outlive the connection, so a per-call directory would split them. Each entry carries the session's
  outbound channel; `DirectoryRegistration` (RAII) unregisters it only if it still holds that handle.
- **D10 refined — no broadcaster task.** `InputArbiterHub::publish` fans the snapshot out
  synchronously when the MODE changed. Every publish runs under the hub core lock, so broadcasts are
  serialized in exactly the order states are published and no session ever sees an older snapshot after
  a newer one; the sends are non-blocking, so it is safe on the capture thread. A joining session is
  greeted under the directory lock (order: directory → snapshot read; publish releases the snapshot
  write before taking the directory), so a greeting can never be overtaken by an older broadcast.
- **`owner_name` is `None` in v1**: signaling carries no technician display names (none on the ticket
  or in `session_participants`); the viewer renders "you" / "another technician" from `owner_session`.
- **Admission (Codex r1/r2):** one hand in flight per session (`HandSlot`) plus a machine-wide cap
  (`MAX_HANDS_IN_FLIGHT` = 4, which also bounds jobs left behind by sessions that ended); both permits
  are taken synchronously before any spawn and live INSIDE the blocking job until
  `hand_input_control` returns. **Contract:** a hand request while that session's own hand is pending is
  IGNORED (no task, no reply); the viewer disables the action until the outcome (the `Owned` snapshot or
  an `Error`), then the technician may retry. `Error` refusals carry no state version — the viewer
  treats them as request-failure notices, never as ownership changes.
- The sender is always the session's own handle (never taken from the message); `to_session` is
  uuid-normalized before lookup; the arbiter re-validates the target at begin and commit.

## 7c. Stage 3c as built — the `input_control_handed` audit event (Codex 3c review folded)

**Correction to §3 and §7 ("no CP change"): the control plane DOES change.** Ingest re-hashes every
agent audit event through Go `encodeAuditAction`, a closed allowlist whose default arm errors; an
unknown kind becomes a 400 `ContentTamperError`, and because a chain is strictly sequential the
session's whole trail wedges permanently (the viewer re-posts the batch forever). 3c adds the Go arm,
byte-identical to Rust `encode_action`, pinned by golden vectors H1 (a hand, four distinct uuids), H2
(a claim, from == to) and H3 (a departed party's nil ids, non-uniform uuid bytes, epoch
0x0102030405060708) in BOTH languages (`audit.rs` :: `audit_golden_input_control_vector_v1`,
`audit_input_control_test.go`). A missing `epoch` is refused, never hashed as 0. D11's list of
exhaustive matches was also wrong: the real set is `strip_nul`, `audit_action_name`, `encode_action`,
the Go switch, and the hand-maintained variant-count test.

- **Event:** `input_control_handed { from_session, from_technician, to_session, to_technician, epoch }`
  — control-plane ids, nil where signaling vouched for none (the chain's own convention) or where that
  party had already left; `epoch` is the new ownership interval's arbitration epoch.
- **Who records it (corrects D11's cross-chain sealing, which would have wedged B's chain):** delivery
  is caller-driven on the caller's own transport, a viewer's forwarder drops other sessions' events, and
  ingest refuses technician/session mismatch. So after a hand COMMITS (inside the blocking job, so a
  cancelled wrapper cannot lose it), `seal_handoff` sends a `SealAudit` directive to each party's own
  hand-off channel — once for a claim — and each session's OWN loop seals into its OWN chain and sends
  `ft_audit` on its OWN FileTransfer channel. Both parties are looked up under one directory lock.
- **No seal behind a hole (Codex 3c HIGH):** a sealed event that is never delivered is a seq hole every
  later event of that chain is refused behind. The arm seals only while input is open; a failed send or
  an unencodable sealed event closes input, so a hole can only ever be the LAST event of a chain — and a
  chain lives for exactly one transport.
- **Deferred:** auditing teardown-to-`Blocked` (the departed owner's directory entry is gone by the time
  the capture thread publishes `Blocked`; its own session end is in its own trail).
- **DEPLOY BARRIER (the CP is a single instance):** the CP with the Go arm must be live BEFORE any agent
  release that emits the kind, and once such agents are out, the CP rollback floor must be raised to at
  least the commit that adds the arm — rolling the CP back below it would wedge every chain holding one.

## 7d. Stage 3d as built — the viewer (Codex 3d review folded)

- `lib/input_handoff.ts` (pure): capability, mode/owner taken ONLY from the agent's snapshot, a pending flag
  (cleared by any snapshot or an `input control:`-prefixed `Error`; a 15 s UI timeout says the result is
  unknown), and the view rules — the action only on the agent's affirmative capability, never for an
  observer (who still sees the badge), only once our own signaling id is known; targets are the other
  non-observer participants; hand from shared or by the owner; claim only when locked.
- **No silent target substitution** (Codex): an explicit pick holds while that technician is present; when
  they leave the pick is VOID even if one other target remains, and the picker stays until the technician
  chooses again. Labels are `Technician <tech8> · session <sess8>` — no ordinals, session-discriminated.
- **Refusal attribution:** every agent hand refusal starts with `input control: ` (host.rs
  `INPUT_CONTROL_ERROR_PREFIX`, pinned both sides); App routes those to the model before generic error
  handling, and shows them in the toolbar row as well as the Session menu.
- **Superseded sessions:** App's transport `onMessage` already drops every frame of a superseded session
  (`isCurrent`) before routing, so no control callback guards itself; `input_handoff.spec.ts` pins it
  (mutating that routing guard turns the regression red).
- Tests: model 14 + ControlClient dispatch/bytes in vitest; `e2e/input_handoff.spec.ts` (6) — hand flow, observer
  rule, claim with our own id, never-advertised negative control, voided pick, superseded-session frames —
  each mutation-checked.

Remaining before release: VM acceptance (two consoles, real keyboard hand-off, stranded-key check on a real
app) and agent release 1.3.19 under the §7c CP-first deploy barrier.

## 7e. Stage 3e — cross-stage hardening (from an adversarial review of stages 1-3d together)

Each stage was reviewed in isolation; a 4-lens review of the whole feature (concurrency, authz, lifecycle,
protocol/audit/UX) with a refuting skeptic per finding confirmed defects that only exist where stages meet:

- **Eligibility tracks effective view-only** (medium): a session that is view-only at runtime (signed policy
  floor, the toggle, a lost guest indicator) could claim or be handed ownership while its input is dropped —
  input dead for the whole machine. Eligibility is now `registered && !observer && !view_only`, re-synced at
  every view-only change; an OWNER losing eligibility resolves to `Blocked` (announced) so another controller
  can claim; the host refuses a hand from a view-only session; the viewer does not offer it.
- **No hand stalls behind queued typing**: `check_hand` (pure) refuses an already-invalid hand before anything
  is touched, then typing is cancelled without waiting, then `begin` (which re-validates). Accepted residual:
  an ownership change between check and begin can cancel typing once for a hand that is then refused. Viewer
  pending timeout 25 s.
- **No stranded keys**: a claim from `Blocked` fences EVERY participant (a hand superseded mid-fence used to
  leave the previous owner's holds behind, with their stale-epoch key-ups dropped); an abandoned fence releases
  its members once while input is `Blocked`.
- **Compatibility mode returns when everyone has left**, so a later lone technician is not locked out.
- Accepted: a session whose monitor announcement never fires is not registered (it has no video either).

## 7f. Windows 11 VM validation summary (agent 0.1.18)

Real installed LocalSystem agent, real viewer (Vite dev server proxied to the lab control plane), three
concurrent sessions from separate browser contexts (tech2 = A, tech1 = B, tech1 again = C), Notepad as the
target app, results read from guest console screenshots:

- **Shared mode**: all three connected; B's control listed both other sessions by technician + session id.
  A typed into Notepad.
- **Hand-off + stranded key**: A held Shift DOWN; B handed control to C. Badges: C "You have input control",
  A and B "Another technician has input control". C typed `owner2 ` — arrived **lowercase**, so A's held
  Shift was released on the guest by the fence. A (`AAA`) and B (`bbb`) typed while excluded — **neither
  landed**.
- **Negative control** (proves the lowercase check can fail): a fresh shared session, A holds Shift while B
  types `upper` → arrived `UPPER`; after A releases, `lower` arrived lowercase. Shared Shift DOES reach the
  guest, so without the fence the hand-off run would have produced `OWNER2`.
- **Reset when empty**: the control run (after every session of the first run had left) started shared, with
  no stale owner.
- **Audit**: `input_control_handed` (epoch 1, result ok) ingested by the lab control plane into BOTH the
  handing and the receiving session's chain — the Go allowlist arm (§7c) works against a real agent.

Remaining: agent release 1.3.19, AFTER the control plane carrying 4f6d0737 is live (§7c barrier).
