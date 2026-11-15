# 53 — Attended sessions: request admin rights mid-session

Status: **accepted design; not implemented yet**. The design supports mid-session
input elevation for attended guests who are administrators (§2.1); other-account
credentials are deferred. Unattended hosts already have per-command elevation
(`agent/src/elevation.rs`) and are out of scope. Review constraints and their validation
are summarized in §9.

## 1. The problem, measured

An attended guest runs the support client (or `agent_host attend`) as themselves, at MEDIUM
integrity. Testing on a Windows 11 VM established that such a process cannot create a high-integrity one
without a UAC consent. In practice the technician hits two walls:

1. **Input into elevated windows is dropped.** UIPI: a medium-integrity process's `SendInput` does
   not reach a window owned by a high-integrity process (an admin Command Prompt, regedit, most
   installers). The technician sees the window (capture of elevated windows works from medium) but
   cannot click or type into it.
2. **UAC prompts are on the secure desktop.** Nothing below SYSTEM can capture or inject there. The
   technician sees a frozen or dimmed frame while the guest decides.

Wall 2 is not solvable for an attended client and this design does not try: the guest always
answers UAC prompts themselves (§5). Wall 1 is what this design removes.

## 2. Design: an elevated INPUT-ONLY helper the guest approves

The technician clicks **Request admin rights**. The guest sees our explanation dialog, then the
Windows UAC prompt for our signed binary. On approval, an elevated copy of the same executable
starts as `elevated-input`, connects to the session process over a private named pipe, and from
then on injects the session's input. Capture, networking, consent, the guest window and the
session key all stay in the original medium process.

Why input-only:

- **No key handoff.** The attended identity is an ephemeral in-memory key that is never written
  to disk (host.rs `run_attend`). Relaunching the whole session elevated would need that key in
  another process, or a second redeem, which a one-time code does not allow. The helper never
  talks to the network and holds no credential.
- **A narrow interface.** The helper accepts only the `InputSink` operations (§3.3).
- **One seam.** The attended path builds one `Arc<dyn InputSink>` (host.rs, `run_attend_after_redeem`).
  A forwarding sink slots in there; `GatedSink`, admission, `release_held`, `cancel_typing` and the
  `RMT_INJECTED_TAG` provenance keep working because the helper injects with the same `SendInputSink`.

**What it grants, stated plainly (Codex r1 Q3).** Input at high integrity is administrator
authority: the technician can open an elevated shell and make persistent machine changes. "Input
only" narrows the INTERFACE, not the authority. The guest dialog says so: "Your technician will be
able to make administrator changes to this computer until the session ends."

### 2.1 v1 scope: guests who are administrators (Codex r1 medium, credentials)

When a STANDARD user approves UAC by typing an administrator's credentials, the helper runs as that
OTHER account. A pipe restricted to the guest's SID rejects it, and widening the ACL to an unknown
account is a separate design. v1 therefore checks BEFORE prompting: the session process's token
must be `TokenElevationTypeLimited` (a split-token administrator). Otherwise the answer is
`Unavailable("the signed-in user is not an administrator")` with no prompt. The "prompt for
credentials" half of the P1 stays open.

## 3. Mechanics

### 3.1 Launch (session process, medium)

1. Preconditions: attended session, controlling technician, consent granted, guest window alive,
   token is `TokenElevationTypeLimited`, no request outstanding, not inside the 60 s cool-down
   after a decline.
2. Pre-dialog (as the promote path does). It names the request and tells the guest what Windows
   will show: "Windows will ask you to confirm. Check that it says **Verified publisher:
   <publisher>**." Cancel → `Declined`, no UAC prompt.
3. Open our own image (`GetModuleFileNameW`) with `FILE_SHARE_READ` only, verify THAT HANDLE with
   WinVerifyTrust and the publisher pin of update_download, and keep it open until the helper
   connects. This is defence in depth, not a closed launch: AppInfo resolves the path again and a
   mutable ancestor directory or reparse point could redirect it (Codex r1 high, path). What the
   guest then sees is the publisher of what Windows will actually run; that, plus §3.2's
   self-check, is the claim. Same-user malware that can redirect the path can also raise its own
   UAC prompt at any time, so this flow adds no capability it lacks, only our dialog's credibility,
   which the publisher line in the dialog addresses.
4. **DLL planting (Codex r1 high, dependencies).** The support client usually runs from Downloads.
   An elevated process must not load a DLL from there. **As built (main 0b670452, 2f34aba4):**
   - Both `agent_host.exe` and `DeskRallySupport.exe` are linked with `/DEPENDENTLOADFLAG:0x800`
     (LOAD_LIBRARY_SEARCH_SYSTEM32 for their static imports; crates/agent-windows/build.rs).
   - `scripts/build-release.ps1` reads `DependentLoadFlags` straight from each staged PE and fails
     the build unless it is 0x800 (no dumpbin dependency, so it cannot be skipped).
   - The helper's entry point calls `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` first
     and exits (code 3) if that fails, before it touches the pipe.
   - An audit of crates/ found no `LoadLibrary*` / `GetProcAddress` call in our code.
   - **Correction to r1-r7:** the planned "every import is a KnownDLL or an API set" test was
     impossible. Both binaries import 14 or more non-KnownDLLs (bcrypt, crypt32, d3d11, dxgi,
     iphlpapi, msi, pdh, powrprof, psapi, sas, userenv, wevtapi, wintrust, wtsapi32). The protection
     is the load flag itself, proven empirically: with a garbage `pdh.dll` / `wtsapi32.dll` beside the
     exe, the flag-0 builds loaded the planted file (`STATUS_INVALID_IMAGE_NOT_MZ`, or a "Bad Image"
     box for the GUI client) and the 0x800 builds ignored it and ran. This also closed a planting
     exposure in the published support client, independent of this feature.5. Create the pipe `\\.\pipe\deskrally-elev-<128-bit random>` with `FILE_FLAG_FIRST_PIPE_INSTANCE`
   (creation failure is fatal: a pre-created name is denial of service, never a connection),
   `PIPE_REJECT_REMOTE_CLIENTS`, one instance, overlapped I/O, and a DACL granting only the
   guest's SID.
6. The request gets a generation number and a **120 s deadline that starts BEFORE the launch**
   (Codex r2 medium). Then `ShellExecuteExW("runas", <image>, "elevated-input --pipe <name>
   --parent <pid>", SEE_MASK_NOCLOSEPROCESS)` runs on a launch worker thread, which may stay
   blocked for as long as the UAC prompt is unanswered. `ERROR_CANCELLED` → `Declined`.
7. The request ends at the first of: a verified connection (steps 8-9); the deadline; the session
   ending; the technician cancelling. On every end but success the request is RETIRED at once: the
   pipe server handle is closed and the request's generation is marked dead, even while the launch
   worker is still blocked. When that worker eventually returns it checks the generation and
   publishes nothing: a late return never yields `Granted` and never revives the request. **We
   cannot dismiss Windows' UAC prompt**; retiring the request only guarantees that a later approval
   is harmless: that helper finds no pipe and exits within its 10 s deadline (§3.2). The viewer
   says "Request expired; if Windows is still asking, the guest can click No."
8. Verify the client is the process we launched, using the process HANDLE we hold:
   `GetNamedPipeClientProcessId(pipe) == GetProcessId(hProcess)` and `hProcess` not yet signalled.
   Mismatch → close everything, `Unavailable("helper did not connect")`.
9. Handshake (1 s deadline): the helper sends `Hello{integrity, user_sid}` read from its own token.
   Must be `High` and the guest's SID. Otherwise `Unavailable`.

### 3.2 Helper (`agent_host elevated-input`, high)

- First: `SetDefaultDllDirectories` (§3.1 step 4).
- Opens the pipe with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` (Codex r1 high,
  impersonation): the medium server can identify the client but never impersonate its high token.
  A unit test connects a test client with these flags, has the server read one message first,
  impersonate, and assert `TokenImpersonationLevel == SecurityIdentification` explicitly (always
  `RevertToSelf` after). A positive control connects WITHOUT the flags and asserts the level is
  `SecurityImpersonation`, so the test cannot pass for an unrelated reason.
- Opens the parent with `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION` by `--parent`, then checks
  `GetNamedPipeServerProcessId(pipe) == --parent`, that the parent's image path
  (`QueryFullProcessImageNameW` on the SAME handle) equals its own, and that the handle is not
  signalled. Liveness and identity come from one process object, so PID reuse cannot swap it.
- Connection deadline 10 s from start; handshake as above.
- Serves frames until any of: pipe EOF or error; the parent handle signalled (an independent
  watcher thread, so a hung read cannot delay it); a malformed or over-length frame; the admission
  lease (§3.3) expired for more than 10 s with no renewal (the session is gone or hung). On every exit path it runs
  `release_held()` on its own sink before returning.
- It creates no windows and has no message pump.

### 3.3 Frames and `ElevatedSink` (session process)

Frames, length-prefixed, at most 8 KiB (a Text event is already capped at 4096 bytes):
`Inject(InputEvent) | SetAdmitted{admitted, epoch} | Renew{epoch, valid_until} | CancelTyping |
ReleaseHeld | ReleaseKeys`.
The helper answers each with one status byte. Every write and read on the session side has a 1 s
deadline; a missed deadline is a helper failure.

**Admission is forwarded and enforced at the helper's final injection boundary (Codex r1 high,
r2 high).** In-order frame processing alone is not enough: a long `Text` being typed would hold a
single thread until it finished. So the helper has two parts:

- a **control reader** thread that only reads frames and never injects or blocks on typing;
- the helper's **sink**: the same `GatedSink(SendInputSink)` the session uses locally, whose typing
  already runs on its own worker and whose `cancel_typing` stops typing that is in progress.

`Inject` frames are handed to the sink and acknowledged on RECEIPT, not on completion, so no ack
waits behind typing. `SetAdmitted(false)` is handled by the reader itself, immediately and not
queued: it closes the sink's admission gate (an atomic epoch), calls `cancel_typing(false)`, and
releases held input, in that order. Every actual `SendInput` (each typed character included)
rechecks the gate first, which is how `GatedSink` already works (`inject_stamped`), so typing that
was queued or mid-way stops at the next character.

On the session side, a revocation must not wait behind other traffic either: the pipe writer has a
priority slot that `SetAdmitted(false)`, `CancelTyping` and `ReleaseHeld` take ahead of queued
`Inject` frames, and taking it needs neither the transition mutex nor any pending ack.

**The revocation bound does not depend on the helper's reader (Codex r3 + r4 medium).** A priority
frame cannot overtake a write already in flight, and closing the pipe only takes effect when the
helper's reader runs. So the helper's authority EXPIRES on its own:

- **An admission lease, on a clock both processes share.** While admitted, the session sends
  `Renew{valid_until}` every `RENEW_EVERY = 50 ms`, where `valid_until = now + LEASE` with
  `LEASE = 250 ms` and `now` is `GetTickCount64()`, the system-wide monotonic millisecond count,
  identical in every process on the machine. The helper keeps `lease_until = max(lease_until,
  valid_until)` for renewals in the current admission epoch only.
- **Checked at every injection.** The sink's per-injection gate (each typed character included) is
  `admitted && epoch == current && GetTickCount64() < lease_until`. Nothing else is required for
  injection to stop: not the reader, not the pipe, not any ack.
- **Admission state and its linearization point (Codex r5 medium, ordering).** The session holds
  one `Admission{epoch: u64, admitted: bool}` behind one mutex. Every change BUMPS the epoch under
  that mutex:
  - revoke: `epoch += 1; admitted = false`. **This store is the linearization point of
    revocation.** After it, no renewal for any earlier epoch can be created.
  - admit: `epoch += 1; admitted = true`.
  - renew: under the same mutex, `if admitted { (epoch, valid_until = GetTickCount64() + LEASE) }`.
    The expiry is fixed WHILE the admission is authorized, before any I/O or delay. A renewal
    created before the revoke therefore expires at most `LEASE` after the revoke, however late it
    is sent or read; none can be created after it.
  The frames carry the epoch they were created in: `SetAdmitted{admitted, epoch}`,
  `Renew{epoch, valid_until}`. Sending happens outside the mutex, so frames from two threads may
  reach the pipe out of order; the helper makes that harmless:
  - it keeps `max_epoch`, and **ignores every frame whose epoch is below it**;
  - `SetAdmitted{false, e}` with `e >= max_epoch`: `max_epoch = e`, gate closed, `lease_until = 0`.
    A revoked epoch is terminal: nothing reopens it, because reopening needs a higher epoch;
  - `SetAdmitted{true, e}` with `e > max_epoch`: `max_epoch = e`, gate open, **`lease_until = 0`**
    (a new epoch starts with no lease; only a renewal of that epoch grants time);
  - `Renew{e, v}` counts only if `e == max_epoch` and the gate is open:
    `lease_until = max(lease_until, v)`.
  So a stale `SetAdmitted(true)` (lower epoch than a later revoke) is ignored, a replayed renewal
  of a revoked epoch is ignored, and a renewal of the current epoch was stamped while it was
  authorized.
- **The bound, stated with its assumption (Codex r5 medium, scheduling).** The gate is checked
  before every injection. Any injection whose gate check STARTS after `lease_until` is refused. So
  after the session's revocation (its linearization point), at most **one** further injection can
  land after `LEASE`: one whose check passed just before expiry and whose `SendInput` was then
  delayed. That delay is the whole wall-clock interval from the final check to `SendInput`
  returning, and an arbitrarily descheduled worker makes it unbounded in time. The honest bound is
  therefore: **no injection whose gate check begins later than `LEASE` after revocation; at most one
  in-flight injection, of one event, may complete later.** The session stops renewing (the revoke
  store) BEFORE anything else on revocation, with no I/O.
- **What makes it ONE event (Codex r6 medium).** The helper has a single helper-wide **injection
  lock**. Every actuating path (typing worker, ordinary `Inject`, `ReleaseHeld`, `ReleaseKeys`)
  takes it, then checks the gate, then calls `SendInput` with exactly **one** `INPUT`, and releases
  the lock only after `SendInput` returns. So at most one passed-check injection exists at any
  moment. A typed character is two events (key down, key up), each with its own lock + check. A
  revocation between them refuses neither the up nor any other release: releases pass a closed
  gate, exactly as `GatedSink` already does, so a key pressed before the revocation is still
  released and the sink's held-key accounting stays exact.
  Releases passing a closed gate are the one deliberate exception to "refused after expiry": they
  can only lift keys, never press them. A release can still have an effect (a button-up can
  complete a drag), so the guarantee is **no new presses after the bound**, not "no effects".
  Held-state accounting is updated under the same injection lock. The reader hands release work
  (`ReleaseHeld` on EOF or revocation) to the injection side WITHOUT waiting for the injection lock,
  so it never blocks behind a `SendInput` (Codex r7 note).
- **Coherent helper state.** `max_epoch`, the gate and `lease_until` live under one helper-state
  mutex; the reader updates them under it, and the gate check reads a snapshot under it while
  holding the injection lock (lock order: injection lock, then state mutex; the reader never takes
  the injection lock, so it never waits behind a `SendInput`).
- **A renewal that arrives before its admission** (out of order) is discarded; input then pauses
  until the next renewal, at most `RENEW_EVERY` later. Accepted.
- **Cleanup, not the bound:** if `SetAdmitted(false)` is not acknowledged within 100 ms, the session
  also closes the pipe (`CancelIoEx`, then `CloseHandle`). The helper treats EOF like
  `SetAdmitted(false)` (gate closed, `cancel_typing`, release held input) and exits. A closed pipe
  ends the grant (`ElevationResult::Ended`); the technician may request it again.
- **Cost:** a session process that stalls for more than 250 ms (a GC-free Rust process, so a
  scheduling stall or a hung async runtime) briefly pauses the technician's elevated input; renewal
  resumes it. That is the right side to fail on.

**Session teardown order:** `SetAdmitted(false)` → `CancelTyping` → `ReleaseHeld` → close the pipe.
The helper exits on EOF. Teardown runs on guest End, view-only, lost indicator, and every other
session end.

**Transitions are serialized (Codex r1 medium, held input).** One mutex covers "which sink is
current" and every inject.
- Local → helper (on Granted): local `release_keys()` first, then switch. Nothing pressed locally
  is still down when the helper takes over, so no release is routed to the wrong sink.
- Helper → local (on helper failure): send `ReleaseHeld` with the 1 s deadline if the pipe still
  works, then switch to local and send `ElevationResult::Ended` to the viewer.
- **Accepted, stated:** if the helper dies abruptly (killed, crashed), its held keys or buttons
  stay down in whatever window had focus until the guest presses and releases them. Local
  `release_held` cannot release them (it never recorded them) and is not attempted for that
  purpose. The guest dialog and the viewer's "Admin rights ended" notice both say "if a key seems
  stuck, press it once".
- A `Text` in progress at a transition is cancelled, not resumed.

The session process cannot terminate the helper (no write-up: a medium process cannot obtain
`PROCESS_TERMINATE` on a high one), so every helper exit is the helper's own decision, driven by
pipe close or parent death.

### 3.4 Protocol

ControlMessage additions (controller ⇄ agent), behind a capability flag in the agent's hello so
old agents never show the button:

- `RequestElevation` (controller → agent). Refused by the agent unless the §3.1 step 1
  preconditions hold. Observers send no actuating messages; the agent refuses this one from an
  observer too.
- `ElevationResult{state: Pending | Granted | Declined | Unavailable{reason} | Ended}` (agent →
  controller).

### 3.5 Audit

The console records `session.elevation_requested` and `session.elevation_result` through the
existing session audit endpoint, keyed by session id. The agent's log records the same
transitions. `Granted` means "the guest approved UAC and our helper connected and passed the
handshake", nothing about what was done with it.

## 4. Security argument

- **Who can raise a UAC prompt:** only a controlling technician in a consented attended session,
  rate-limited, and only after our pre-dialog.
- **What a grant gives:** administrator authority through input (§2), until the session ends.
- **Residual (Codex r1 Q3):** while a grant lives, code that takes over the medium session process
  can drive the helper. A guest-window flag cannot prevent that (same process). Bounds: the helper
  exits on pipe close and parent death, and admission revocation is enforced in the helper. This is
  the same trust the guest already extends to the session process for their own desktop; what grows
  is the reach, which is why the dialog says "administrator changes".
- **No impersonation of the helper** (§3.2), **no DLL planting** (§3.1 step 4).
- **No silent elevation by us:** with "never notify" UAC, ShellExecute elevates without a prompt;
  our pre-dialog is then the only consent and it is mandatory.
- **Unattended hosts:** the agent refuses `RequestElevation` there.

## 5. Viewer

- Session menu, attended sessions with a capable agent, controlling only: **Request admin rights**.
- States in the session bar: "Waiting for the guest to approve…", "Admin rights granted", "The
  guest declined", "Admin rights unavailable: <reason>", "Admin rights ended".
- Standing hint while waiting or granted: "Windows security prompts appear only on the guest's
  screen; ask the guest to answer them."

## 6. Tests

Unit (agent-core): ControlMessage round trips; capability gating; preconditions; decline cool-down.

Unit (agent-windows):
- frame codec, including over-length and malformed frames ending the helper;
- `ElevatedSink`: admission forwarded and ordered before later input; teardown order;
  local → helper switch releases local keys first; helper failure falls back to local; deadlines;
- pipe trust: a second process that connects first is refused (PID mismatch); the
  identification-only client cannot be impersonated (§3.2);
- the load-flag check in build-release.ps1 and the planted-DLL launch in the VM (§3.1 step 4).

VM self-test (test-harness `agent_host elevated-input-selftest`, `accept/run-elevation-selftest.ps1`):
PASS 2026-10-29 on a2-fresh-noagent-bundle, run as a medium-integrity admin under
`ConsentPromptBehaviorAdmin=0`. It drives the REAL path — `ShellExecuteEx("runas")` launch of the
elevated helper, pipe connect + handshake, attach, forward input, detach — and asserts granted,
attached, ended, and that the helper process exits with nothing left. This is what the unit tests mock.

VM (DeskRally-Accept-20261015; the only place this is real), guest an administrator:
- (a) before a grant, a click into an elevated cmd.exe does not land (UIPI baseline);
- (b) approval under the default UAC policy: the scheduled-task harness cannot click on the secure
  desktop, so this case runs with `ConsentPromptBehaviorAdmin = 5` while the host operator approves
  through the VM console (Hyper-V's console CAN reach the secure desktop); then the same click lands
  and typed text appears;
- (c) explicit Cancel on the UAC prompt, via the VM console → `Declined`;
- (d) unanswered prompt → at 120 s the request retires (`Unavailable("expired")`) although the
  launch worker is still blocked; a later approval starts a helper that finds the pipe closed and
  exits within its 10 s deadline, and the viewer never shows `Granted`;
- (e) revocation during ACTIVELY executing typing: a long Text is mid-way into an elevated
  Notepad when the technician switches to view-only (and, separately, the guest clicks End); the
  typed text stops within the §3.3 bound (`LEASE` + one injection), measured by timestamps
  against the character count;
- (e2) unit, the lease alone: a helper whose control reader is PAUSED for 2 s (well beyond `LEASE`)
  while its typing worker types a long Text; the session revokes; injection must stop within
  `LEASE` + one injection, BEFORE the reader resumes, with renewals still buffered in the pipe.
  Variants: renewals of an old epoch after `SetAdmitted(true)` do not extend the new epoch; a
  renewal read late cannot push `lease_until` past its own `valid_until`;
- (e2b) unit, the worker paused AFTER its final gate check (a test hook between check and
  `SendInput`) past expiry: exactly that one event lands late and the next check refuses. Race
  variant: typing AND ordinary `Inject` input concurrently, both with the post-check hook armed;
  the recording `SendInput` double sees at most one press-type event after expiry (releases
  excepted, by design);
- (e2c) unit, races on the session side (loom-style interleavings or a seeded scheduler): revoke
  vs a renewal being constructed; revoke vs a pending `SetAdmitted(true)` sent from another
  thread; frames delivered out of order. In every interleaving the helper's gate is closed after
  the revoke's epoch arrives, and no renewal it accepts expires later than `revoke + LEASE`;
- (e3) unit, cleanup: no ack within 100 ms closes the pipe; on EOF the helper closes its gate,
  cancels typing and exits;
- (f) killing the session process ends the helper within 1 s; graceful paths leave no key down;
- (g) killing the helper while a key is held: the key stays down (the stated limitation), the
  viewer shows "Admin rights ended", local input resumes;
- (h) a standard-user guest gets `Unavailable` with no prompt.

Viewer e2e: the button only for attended + controlling + capable; the observer never sees it; each
state's text.

## 7. Out of scope

- The secure desktop (§1, wall 2). Promote (shipped) is the answer when a technician needs it.
- Relaunching capture elevated. Capture works from medium.
- Credentials of another account (§2.1).
- Unattended hosts.

## 8. Open questions for review

1. §3.1 step 3 now claims only "the guest sees the publisher of what runs". Is that honest and
   sufficient, given same-user malware can raise its own UAC prompt anyway?
2. (Answered at r2; the allowlist part was later found impossible, see §3.1 step 4.) Is `/DEPENDENTLOADFLAG:0x800` plus `SetDefaultDllDirectories` plus the import allowlist enough
   against Downloads DLL planting for this binary?

## 9. Implementation constraints and validation

| Constraint | Implementation and validation |
|---|---|
| helper token impersonable by the medium pipe server | §3.2 SQOS identification + test |
| path resolution and dependency loading not secured | §3.1 steps 3 and 4: claim narrowed; DLL search locked to System32 + import test |
| `set_admitted` not forwarded; teardown undefined | §3.3 admission frame, ordering, teardown order; §3.1 step 7 late helper |
| credential elevation breaks same-user DACL | §2.1: v1 is admin guests only, checked before prompting |
| held-input accounting across transitions | §3.3 serialized transitions; abrupt-death limitation stated |
| test plan gaps | §6 cases (b)-(h) |
| Q5: bounded frames, cancellable IPC, helper deadlines | §3.2, §3.3 |
| revocation could wait behind executing Text | §3.3 control reader + gate rechecked per injection + session-side priority slot; §6(e) active typing |
| deadline started after a possibly blocked ShellExecuteEx | §3.1 steps 6-7: deadline first, generation-retired request, late return publishes nothing; §6(d) |
| r2 Q3 qualifications | §3.1 step 4: load-config flag checked, fail closed, LoadLibrary audit |
| r2 Q4 qualifications | §3.2: explicit level assert, read-before-impersonate, RevertToSelf, positive control |
| revocation latency unbounded behind an in-flight write | §3.3 admission lease (r4) |
| pipe close relies on the paused reader | §3.3 helper-side lease on GetTickCount64, absolute-expiry renewals per epoch, checked at every injection; §6(e2) reader paused beyond the bound |
| bound ignores a worker paused after its check | §3.3 bound restated: no check after `LEASE`, at most one in-flight event later; §6(e2b) |
| "one late event" needs helper-side serialization | §3.3 helper-wide injection lock, one `INPUT` per `SendInput`, releases pass a closed gate, coherent helper state; §6(e2b) race variant |
| revoke / renewal / admit ordering undefined | §3.3 admission mutex, epoch bumped on every change = linearization point, expiry stamped under the mutex, helper ignores lower epochs, terminal revoked epochs, new epoch starts with no lease; §6(e2c) |
