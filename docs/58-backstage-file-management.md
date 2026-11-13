# docs/58: Backstage file management and "silent operations"

**Status:** design r11, 2026-10-30. Ten Codex review rounds (r1-r10, all repairs; see §10). Closes the parity item "P1 Silent operations expectations for Backstage (clipboard/file drop without
user visibility)" and the missing half of "P1 File Manager" (new folder / rename / delete, drop files
where you browse). It also fixes a live defect: no confirmable Backstage action can complete today
(§3).

## 1. What "silent" means here (the expectation, written down)

DeskRally never hides that a technician is connected. The guest window's **presence pill** ("A
DeskRally technician is controlling/viewing this PC") is always on and cannot be dismissed, only
collapsed. A session that cannot show it at start is an observer (`host.rs` ~4070: `observer ||
indicator_missing`). docs/04 says: "never ship a mode designed to hide the tool from the machine's
owner". None of that changes.

"Silent operations" therefore means **Backstage adds no per-action prompt or popup for the person at
the PC.** It does not promise the action is invisible: an action's own effects may show (a folder
appears on the desktop, a stopped service's app reports an error, a shell runs a program that opens
a window).

| Operation | Backstage adds for the guest | Recorded |
|---|---|---|
| Processes / services / registry / event log / shell | nothing beyond the pill | this session's Backstage audit chain, incl. denials |
| File browse, upload, download (existing) | nothing beyond the pill | `file_browse`, `file_transfer` (+ sha256) |
| **New:** new folder, rename/move, delete, place an upload | nothing beyond the pill | `file_create_dir`, `file_rename`, `file_delete`, `file_place` |
| Clipboard crossing (either direction) | **a notice** (unchanged, by decision) | clipboard events |

The clipboard stays announced because a guest's clipboard often holds what they just typed
(passwords; `guest_ui.rs`). Backstage gets no clipboard tool.

**Presence loss gates mutations (r2, r3).** Today, if the indicator is lost mid-session, the session
drops to view-only for INPUT (`IndicatorVisible(false)` → `view_only`), but the Backstage dispatch
still uses the start-of-session `observer` flag. r3 gates every mutation channel the moment
`indicator_lost` becomes true, not only new requests:

- **New requests:** a non-read-only Backstage request, an upload `Offer`, a download of a new file
  and a shell open are refused, each with the same reason text.
- **Uploads in flight:** they are ABORTED. No further chunk is written and no `Done` is committed;
  each `.part` is deleted by handle; each is audited `file_transfer` with outcome `Failed`
  ("indicator lost"); and the sender receives a failed ack.
- **Open shells:** they are CLOSED. Their input stops at once, the ConPTY process tree is terminated,
  and the close is audited `shell_close` with the reason in the transcript record. The technician
  sees "shell closed: the guest's indicator could not be shown".
- **Reads:** read-only tools keep working.
- **When the indicator returns:** new requests are allowed again. Nothing aborted is resumed: aborted
  work belongs to an invalidated generation (below) and can never be admitted again.

**Execution model (r6).** Presence loss must never wait on file work, and work cut off by it must
never come back.

- **A revocation GENERATION, not a boolean.** `MutationGate` holds `generation: AtomicU64` and
  `open: AtomicBool`.
  - Every unit of mutating work is stamped at ADMISSION with the generation current when it was
    accepted: a Backstage mutation, an upload (at its `Offer`), and a placement.
  - Presence loss increments the generation and clears `open`. Presence return sets `open` again
    WITHOUT touching the generation.
  - So all pre-loss work carries a dead generation forever, and a returning indicator admits only
    new work.
- **The admission point and the exact contract.** Before each irreversible system call (create,
  rename, dispose, chunk write, upload commit), the code performs ADMISSION: `open &&
  stamped_generation == generation`. The contract:
  - **No call is admitted after revocation.**
  - A call admitted before revocation may still start and finish afterwards (the check-to-submit
    gap cannot be closed with atomics, and no claim is made that it is).
  - Outstanding admitted calls are bounded: at most ONE per executor, i.e. one on the Backstage
    worker and one on the upload writer. The audit records each one's real outcome.
- **All file I/O runs off the receive loop.**
  - Backstage requests run on one dedicated blocking worker, serially, in arrival order, so replies
    stay FIFO.
  - **Uploads are owned by ONE upload-writer thread (r8).** It holds every upload's state: the
    staging handle, the `.part` handle, the hasher and the terminal state. It is the only code that
    writes, commits, aborts, cleans up, acks or audits an upload. The loop never touches upload
    state. It only:
    - forwards each chunk and `Done` frame to the writer through a BOUNDED channel of 64 items
      (order preserved), using `try_send` and never awaiting;
    - sets the upload's permanent cancel flag, an `Arc<AtomicU8>` created at `Offer` time and
      shared with the writer: 0 = live, then a reason code (indicator lost, queue overflow, session
      end). Once set it never clears.
  - **Overflow (no presence loss involved).** When `try_send` finds the channel full, the loop sets
    that upload's cancel flag ("this machine's disk is not keeping up") and drops the frame. Every
    later frame for that upload is dropped by the loop as well, because the flag is set. The loop
    sends NO ack. The writer acks. Nothing is queued for cleanup.
  - **The writer discovers cancellations itself.** Before every admission (each chunk write and the
    commit), and between items, it checks the flags of all the uploads it owns. A cancelled upload
    is finished by the writer:
    - it disposes the `.part` file by its OWN handle (idempotent, not admission-gated);
    - it sends the failed ack;
    - it writes the ONE terminal audit record;
    - it drops the state.

    Cleanup therefore needs no queue capacity and cannot be stranded by later losses or overflows.
  - **The writer never sleeps past a cancellation (r9).** It waits for its next item with
    `recv_timeout(250 ms)`, never an unbounded `recv`. On every wake, whether an item or a timeout, it
    scans the cancel flags of the uploads it owns before doing anything else. An idle upload that was
    cancelled is therefore finished within 250 ms (plus any one system call already in progress), with
    no further transfer frame and no queue capacity needed.
  - **Session teardown (r10, r11) revokes FIRST.** Every teardown path (end by either side, transport
    loss, error, guest End) begins by closing `MutationGate` and advancing its generation, before the
    guest window and pill are removed and before any session resource is released. That is the same
    revocation as presence loss. So queued Backstage mutations carry a dead generation and are
    rejected (each answered `refused` if the channel is still up, and audited as denied, "session
    ended"). The worker accepts no new work. At most the ONE already-admitted call can finish. If it
    outlives shutdown, the Backstage worker keeps ownership of its handles and writes the real outcome
    to the agent log, exactly like the upload writer below. Then teardown sets every live upload's
    flag ("session ended") and drops the channel. Shutdown is bounded, but cleanup is only eventual:
    - **Within 5 s:** the session waits up to 5 s for the writer to finish every upload (dispose plus
      the terminal audit in the session chain; no ack, since the peer is gone).
    - **If the writer is still inside a system call at 5 s:** the session does NOT wait longer and
      does not touch the writer's resources. It seals each unfinished upload into the chain as
      abandoned, as today's teardown seal does. That seal is the upload's ONE terminal chain record,
      and the writer is told so through the same per-upload state.
    - **The writer keeps ownership** of its handles, flags and transfer-root handle until that call
      returns. It then disposes the `.part` files and records the real outcome to the AGENT LOG (not
      the chain, which already holds the seal), then exits.
    - **What is promised:** session shutdown completes within 5 s. Cleanup completes after the
      stalled call returns. A commit admitted before teardown may still land; its file is then an
      ordinary completed upload in the trusted root (the agent log says so), never a corrupt one.
    Until the writer has finished an upload, it keeps the state (bounded: at most 4 concurrent
    uploads per session, as today).
  - **Commit against abort, one terminal outcome.** Commit admission is: the cancel flag is clear,
    `open`, and the generation matches. It is checked by the writer immediately before the commit
    rename.
    - **Cancelled before admission:** the abort path above runs. Terminal record `Failed` (reason),
      failed ack, `.part` disposed.
    - **Admitted:** the commit runs to completion, even if revocation or overflow happens meanwhile.
      Its REAL result is the terminal outcome. If the file landed: terminal `Ok`, ok ack, and the
      file stays in the root, placeable by `transfer_id` as usual (it is a completed upload). If the
      rename failed: terminal `Failed`, `.part` disposed.

    No path both commits and deletes, because the deletion only ever targets the `.part` handle,
    which a successful commit has already renamed away (disposal of a renamed handle is skipped by
    state, not attempted).

- **Hashing is cancellable.** `PlaceUpload`'s re-hash checks admission between chunks.
- **Tests:**
  - stall a real chunk write on a seam and drop the indicator: the loop processes the event and the
    shell process is gone within 1 s;
  - stall the Backstage worker between admission and the system call, revoke, then release: the
    admitted call finishes, is audited, and nothing further is admitted;
  - drop and then restore the indicator while cleanup is still blocked: old chunks, the old `Done`,
    the old hashing and queued old mutations are all refused (dead generation), and a NEW upload
    works;
  - a mid-hash drop refuses the placement;
  - stall the writer, FILL its queue, then drop the indicator: revocation and shell termination
    still happen within 1 s; once released, the over-full upload gets a failed ack;
  - overflow without presence loss, repeated overflows, and two losses while the writer is stalled:
    once released, every `.part` file is removed and each transfer has exactly ONE terminal audit and
    one ack;
  - an IDLE upload (empty queue, no more frames sent) when the indicator drops: within 1 s, its
    `.part` file is gone, exactly one failed ack and one terminal audit are recorded, and its slot is
    free;
  - session teardown with idle and active uploads: all finished within 5 s;
  - stall the Backstage worker, queue several mutations, end the session, then release: only the
    already-admitted call executes, and the queued ones are rejected and audited as denied;
  - teardown with a system call stalled beyond 5 s: the session ends at 5 s with one "abandoned"
    chain record per unfinished upload; once released, the writer disposes the `.part` file, logs the
    real outcome to the agent log, writes nothing more to the chain, and exits;
  - revoke after commit admission with the rename stalled: once released, the commit's real result
    is the single terminal outcome. If it landed, the file stays and is placeable; no `.part`
    deletion is attempted.

Console help line (Under the Hood): "The person at this PC sees that a technician is connected,
but no prompt for each action here. Each action is recorded in this session's audit trail."

## 2. Feature negotiation and channel robustness (r2)

Old agents must never receive a request they cannot decode. They drop it with no reply
(host.rs ~5379), and the viewer's FIFO correlation (`channel.ts`) would then pair every later reply
with the wrong request.

- **Advertisement:** after `GrantInstalled`, a new agent sends a new control message
  `BackstageFeatures { features: ["confirm", "file_manage"] }`. The viewer enables the confirm retry
  and the file-management controls ONLY after receiving it. Old viewers drop an unknown control
  message (control.ts decodes unknown `t` to nothing). An old agent never sends it, so the controls
  never appear against it.
- **No silent drops (new agents):** a malformed or unknown Backstage request now gets a well-formed
  `ok:false` envelope (`kind: "refused"`, "this agent does not understand that request") instead
  of no reply. Every frame gets exactly one reply.
- **Viewer send failure (r4):** if `send` throws, the transport is closed AT ONCE: every pending
  request is rejected, including the one whose send failed, and the session-level disabled state is
  set, exactly as on a timeout. A queued resolver is never left behind for a later reply to satisfy.
- **Viewer (r3):** if a reply does not arrive within 60 s, the Backstage transport is CLOSED: every
  pending request is rejected, and the tab says "Under the Hood stopped responding; reconnect the
  session to use it again". It is NOT reopened on the same session. A late reply from the timed-out
  request could still be in flight, so any new FIFO adapter on that channel could pair it with a new
  request. Only a new session, which means a new WebRTC data channel, brings the tab back. Explicit
  request IDs would allow a reopen; they are not needed for a 60 s failure that should never happen,
  and the reconnect rule is simple to prove.

## 3. Typed confirmation over the session channel (fixes a live defect)

Step 3 of the dispatcher needs `Confirmation::Provided` for confirmable actions. These are registry
writes under sensitive keys, `ShellAsCredential`, `RegistryHiveLoad`, `UninstallProgram`, and the new
file guard rails. The HTTP seam carried that as `?confirm=1`. Over the WebRTC channel, every frame is
dispatched with `NotProvided` (host.rs ~5374), so the viewer's type-the-machine-name dialog retries
into the same `needs_confirmation` forever.

**Wire (r3):** a `needs_confirmation` envelope from a new agent carries `confirm_token`, a hex string.
The agent computes it as SHA-256 over:

- the request's canonical JSON;
- for file operations, the RESOLVED operand identities (volume serial + file id of each object it
  would act on, and of the destination parent);
- the session id.

The retry repeats the request with a top-level `"confirm": "<token>"` beside `type`/`data`. The agent
re-resolves everything and maps the request to `Confirmation::Provided` only if the recomputed token
equals the one sent. If anything changed between the dialog and the retry (for example, a local user
replaced the folder), the agent answers `needs_confirmation` again with a new token, and the dialog
reappears showing the new resolved paths. The viewer sends `confirm` only to an agent that advertised
`"confirm"`.

**What it means (r2, stated plainly):** the token binds a retry to the exact objects the dialog
showed. It is still only a client ASSERTION that the console's dialog was completed: a UX safeguard
against a mis-click or a swapped target, not an authorization boundary. A principal who can send
Backstage frames already holds the capability. The audit records the outcome of the
confirmed action. It does not record "a human typed the name", and no document may claim it does.
A short-lived server challenge bound to the exact operation would be the upgrade if confirmation ever
needs evidential weight. That is out of scope here.

**Compatibility:** for EXISTING request types, an older agent's adjacently tagged serde decode
ignores the unknown key (no `deny_unknown_fields`) and answers `needs_confirmation`. A test pins
that. The viewer anyway sends `confirm` only to agents that advertised it (§2).

## 4. New Backstage requests

All four are **Admin tier, gated on the existing `file_delete` capability**, whose meaning this
design deliberately WIDENS (r2) from "delete" to "manage files outside the transfer folder".

- **Why widen:** the agent acts as SYSTEM, so creating, moving or deleting anywhere on disk is
  admin-equivalent. The Operator-tier `FileUpload` stays safe only because it is confined to the
  transfer root.
- **Why not a new capability:** a grant naming a capability an older agent does not know fails to
  deserialize there, which would break Backstage on every not-yet-updated agent.
- **Who holds it:** the only issuer is `BackstageCapsFor` (grant.go). It mints `file_delete` only with
  `CapManageMachines` for the machine's group, and in the same tier as `shell_as_system`, which
  already allows anything as SYSTEM. API tokens do not mint Backstage grants.
- **What changes for operators:** no existing holder gains anything they could not already do. The
  role-reference text and docs/04 are updated to say "file management".

```
CreateDirectory { path }                  -> Ack      audit file_create_dir { path }
RenamePath      { from, to }              -> Ack      audit file_rename { from, to }
DeletePath      { path }                  -> Ack      audit file_delete { path }            (existing kind)
PlaceUpload     { transfer_id, dest_dir } -> Ack      audit file_place { transfer_id, sha256, to }
```

Audited paths are the RESOLVED ones: the normalized final path of the object actually touched
(§5 refuses every reparse point, so they differ from the request only in case and 8.3 aliases).

- **`DiscardUpload { transfer_id }` (r3):** deletes a completed upload that will not be placed. The
  provenance checks are the same as `PlaceUpload`'s: a session record, identity, and a regular file
  relative to the held transfer-root handle. It is consumed once. It is gated on `FileUpload`
  (Operator), because it removes only what this session's own upload created. It is audited as
  `file_delete` with the resolved path. It is the ONLY way to remove anything inside the transfer
  root: §5's Deny on protected directories stays absolute for `DeletePath`.
- **`CreateDirectory`:** one level only (the parent must exist). Fails if the name exists.
- **`RenamePath`:** a rename, or a move within the same volume. **It never overwrites:** the rename
  is by handle with `ReplaceIfExists = false`. Cross-volume moves are refused, never done as
  copy+delete.
- **`DeletePath`:** a file, or an **empty** directory. There is no recursive delete. A link or
  junction is deleted as itself, never followed.
- **`PlaceUpload` (r2):** moves a file THIS SESSION uploaded, identified by its `transfer_id`, not by
  its name.
  - When an upload commits, the agent records `transfer_id → (landing name, verified sha256, file
    identity)` in a per-session map.
  - `PlaceUpload` opens the landing file relative to the held transfer-root handle. It refuses unless
    the file is a regular file, not a reparse point, and its identity matches the record.
  - It then re-hashes the file through the same handle, opened with read sharing only so the bytes
    cannot change underneath, and refuses unless the digest equals the recorded sha256. This covers a
    custom `transfer_dir` that is not DACL-locked.
  - It moves the file by handle into the destination directory, no overwrite.
  - The record is consumed: a `transfer_id` places at most once.
  - If a later upload of the same name replaced the landing file, its identity differs, so placement
    is refused ("this upload was replaced; upload it again").

`is_read_only()` is false for all four, so an observer session cannot send them.

## 5. Path resolution: handle-relative, no reparse traversal (r2, replaces r1's canonicalize)

**Upload landing is handle-relative too (r3).** Today's upload path creates, checks and opens
`<transfer_dir>\.rmt-staging\<id>.part` BY NAME (host.rs ~8269-8290), then commits by name. In the
default root (`C:\rmt-agent\transfers`, DACL-locked) no non-admin can stage a swap. A CUSTOM
`transfer_dir` that a local user can write is a SYSTEM-write primitive, because the user can swap
staging or an ancestor between the check and the open. r3 closes it for every upload, not only for
placement:

- **The root is trusted, or uploads are off.** At session start, a host running as SYSTEM opens the
  transfer root with `anchor::Anchor::open_at`. It must be a plain directory, owned by SYSTEM or
  Administrators, whose DACL grants no other principal a mutating right, and whose parent grants
  none `FILE_DELETE_CHILD`. If validation fails, uploads and placement are refused for the session
  ("the transfer folder is not protected; uploads are disabled on this machine").
- **The root is the agent's own, or uploads are off (r5).** Trust is not purpose. An
  administrator-owned `C:\Vendor\Service` would pass any ACL check, yet planting an absent DLL there
  is a SYSTEM code-execution primitive, and an exclusion list cannot prove a directory harmless. So a
  host running as SYSTEM accepts exactly ONE transfer root: the agent-provisioned `transfers`
  directory inside the anchored config root, verified by file identity (opened relative to the
  `C:\rmt-agent` anchor handle, not by name).
  - A configured `transfer_dir` that names anything else disables uploads and placement for the
    session ("uploads use the agent's own transfer folder; transfer_dir is ignored on this machine")
    and logs a warning.
  - The installer already writes the default (`build-release.ps1` config template), so no shipped
    machine changes behaviour.
  - Pre-existing per-machine overrides, if any, lose uploads rather than keep an escalation path.
  - The attended support client (not SYSTEM) is unaffected.
- **Uploads never replace a file (r4).** Today's commit replaces an existing name ("last upload of a
  name wins"). r4 commits by handle with `ReplaceIfExists = false`. On a collision it lands as
  `name (2).ext`, `name (3).ext` and so on, up to 99, and then refuses; the ack carries the name
  actually used. A pre-existing file in the root is never overwritten by any upload, and a placed
  file is found by `transfer_id`, never by name.
  - The attended support client runs as the logged-in user, not SYSTEM, so it has nothing to
    escalate; it keeps its per-run root and current behaviour.
  - The default root always passes, because `harden_agent_root` owns it.
- **Every step is by handle.** The anchor handle is held for the whole session. Staging is a
  validated child dir. `.part` files are created relative to it (`FILE_CREATE`, never reused).
  Commit renames by handle into the root with `ReplaceIfExists = false` (unique landing names, see
  above). Abort and cleanup delete by handle. These are the
  same primitives `anchor.rs` uses for updater state.

r1 canonicalized by NAME and then acted by NAME. That is a TOCTOU race in which a local user can
swap a junction and turn a technician's action into a SYSTEM write elsewhere. It also failed to pin
`PlaceUpload`'s destination. r2 acts only through held handles, on the pattern that `anchor.rs`
already uses for updater state:

1. **Syntax first, before any filesystem access:** the path must be absolute, `X:\...`, and on a drive
   whose `GetDriveTypeW` is `DRIVE_FIXED` or `DRIVE_REMOVABLE`. UNC paths, `\\?\` and `\\.\` paths,
   mapped and remote drives, `.`/`..` components and alternate data streams are all refused. A
   component may not have a trailing dot or space, any of `<>:"/\|?*`, a control character, or a
   reserved device name. Reuses and extends `panels/local_path.rs`.
2. **The walk:** open the volume root (`\??\X:\`), then each component RELATIVE to the previous
   handle with `NtCreateFile` and `OBJ_DONT_REPARSE`. An attempt to traverse any reparse point
   (junction, symlink, mount point, or a cloud or network placeholder) fails with
   `STATUS_REPARSE_POINT_ENCOUNTERED`, and the request is refused ("a link or junction is on this
   path; open its target directly"). Each directory handle is held WITHOUT `FILE_SHARE_DELETE` until
   the operation ends. While it is held, no one can rename or delete that directory, so nothing
   between the check and the act can change.
3. **The act:** done relative to the held parent handle:
   - create: `FILE_CREATE` and `FILE_DIRECTORY_FILE`;
   - delete: open the final component with `FILE_OPEN_REPARSE_POINT`, then dispose by handle;
   - rename and place: rename by handle with `RootDirectory` = the held destination-directory handle
     and `ReplaceIfExists = false`.

   The final component is opened as itself and never followed. Delete removes a link itself; rename
   moves a link itself.
4. **Operand semantics:**
   - `CreateDirectory`: walk the parent and act on the new name.
   - `DeletePath`: walk the parent and act on the final object.
   - `RenamePath`: walk BOTH parents (from and to) and act on the final object of `from`. The two
     parents must be on the same volume.
   - `PlaceUpload`: walk `dest_dir` ITSELF, the full path including its last component, because it is
     traversed; the new child takes the landing name. The source is the held transfer-root handle.

**Protected objects (Deny, any tier):** the agent's config root `C:\rmt-agent` (`CONFIG_DIR`: config,
keys, update manifest, transfers, recordings), its service-binary directory `C:\rmt-agent-bin`
(`BIN_DIR`), and the directory of the running executable. At dispatcher construction the host opens
each one and records its **file identity** (volume serial + file id, `anchor::file_identity`), along
with the identities of all its ANCESTORS. The protected identities are handed to the `Dispatcher` the
same way as `own_service_image`; the portable dispatcher keeps no Windows paths. An operation is
denied when:

- any directory handle in a walk has the identity of a protected root, so the target would be inside
  one; or
- the object it would rename or delete IS a protected root or an ancestor of one. Renaming `C:\Apps`
  must not relocate `C:\Apps\DeskRally`.

Comparison is by identity, so case, 8.3 aliases and `\\?\` spellings cannot evade it. Files placed out
of the transfer root leave it only through `PlaceUpload`. No mutation targets inside a protected
directory.

**RequireConfirmation:** every `DeletePath`. Also any operation whose source or destination resolves
(by identity, using the same ancestor-identity method) under `%SystemRoot%`, `%ProgramFiles%`,
`%ProgramFiles(x86)%` or `%ProgramData%`, or whose target is a direct child of a volume root. For
`RenamePath`, either operand being sensitive is enough.

Non-Windows builds (tests on other platforms) compile the requests but return `exec_failed`
("file management is only available on Windows agents"). Tests that exercise the real behaviour run
on Windows.

## 6. Audit (Rust + Go canonical encoders)

There are three new `AuditAction` kinds. The existing kinds and their encodings are unchanged:

```
file_create_dir : str(path)
file_rename     : str(from), str(to)
file_place      : uuid(transfer_id), str(sha256), str(to)
```

- **Encoders:** Rust `canonical.rs` and Go `audit_canonical.go` both gain the three kinds, with
  shared golden vectors, and a full-chain vector containing every new kind.
- **Deploy order:** the CP verifies ingested chains, so a CP that does not know a kind cannot verify
  the chain. The CP ships FIRST, and the agent release comes after the CP is live. A CP rollback
  below the release that adds these kinds is prohibited once any 1.3.17+ agent may have emitted them.
  The GO says so.
- **Help text:** "recorded in this session's audit trail". It does not say "centrally audited",
  because central ingestion is best-effort (`mod.rs` notes chains the CP may refuse).

## 7. Console (viewer)

- **Where:** the Under the Hood file browser (`FileBrowserPanel`) gets new controls, shown only when
  the grant holds `file_delete` AND the agent advertised `file_manage`:
  - a "New folder" toolbar button;
  - per-row "Rename" and "Delete";
  - "Upload here" (pick or drop files).
- **No mutations in the drive list:** the top-level drive listing shows no mutation controls.
- **Upload here:**
  - The destination is FROZEN, and displayed, when the upload starts. Navigating away does not change
    it.
  - Each file uploads over the existing file-transfer channel to the transfer folder, and is then
    `PlaceUpload`ed by `transfer_id`.
  - The UI reports two distinct steps: "Uploaded" and "Placed in <dest>". If placement fails, it says
    so and offers "Discard upload" (`DiscardUpload`) or "Try placing again". The file meanwhile stays
    in the transfer folder.
  - A destination on a different drive from the transfer folder is refused BEFORE uploading ("files
    can only be placed on drive C: in this version").
- **Confirmation:**
  - The existing type-the-machine-name dialog now completes (§3).
  - It shows the exact resolved path(s) the agent reported.
  - A mutation whose outcome is unknown (channel closed mid-request) is never retried automatically.
- **After each change:** errors show inline (the envelope's `refused`/`exec_failed` text) and the
  listing refreshes after each success.
- **Help line:** the §1 text.

## 8. Not in scope

Recursive delete, copy, overwrite, cross-volume move, a Backstage clipboard tool, any change to the
presence pill, server-verified confirmation (§3), and a hidden GUI desktop (docs/04 Part 2).

## 9. Tests

- **Rust unit (portable):**
  - each request's capability (an Operator grant is refused);
  - `is_read_only`;
  - the syntax rules (UNC, `\\?\`, `\\.\`, `..`, ADS, reserved names, trailing dot or space, a mapped
    or remote drive type through a seam);
  - `confirm` decodes to Provided, and its absence to NotProvided;
  - the SHIPPED 0.1.16 decoder shape ignores `confirm` (a fixture of the old enum);
  - malformed and unknown requests get a refused envelope.
- **Rust Windows (real filesystem, temp dirs):**
  - create/rename/delete happy paths;
  - rename never overwrites;
  - delete is empty-dir-only;
  - a junction anywhere on the path is refused;
  - a junction or symlink as the final component is deleted and renamed as itself, and its target
    survives;
  - **an adversarial swap:** a thread replaces an intermediate directory with a junction into a
    protected test root while the walk holds its handles. The swap fails with a sharing violation,
    and the op still lands in the original;
  - identity-based deny: the protected root, via an 8.3 short name, via a different case, and an
    ANCESTOR rename;
  - `PlaceUpload`: identity mismatch after a replacing upload, digest mismatch, consumed once,
    unknown id, a cross-volume dest refused;
  - presence loss refuses mutations and allows reads; it aborts an ACTIVE upload (no commit, `.part`
    gone) and closes an OPEN shell;
  - upload landing: an untrusted custom transfer root disables uploads under SYSTEM; a staging-dir
    swap to a junction fails, because the handle is held and the child is opened relative to it;
    commit and abort run by handle;
  - the confirm token: a matching retry proceeds; a target replaced between the dialog and the retry
    gets `needs_confirmation` again with a new token;
  - `DiscardUpload` provenance and single use;
- **Viewer (r3):** a timeout closes the tab for the session; a late reply after the close is ignored
  and never answers a new request.
- **Canonical audit:** Rust and Go golden vectors for the three kinds, a mixed full chain, and CP
  ingest of it.
- **Viewer unit:** `confirm` is sent only after advertisement; the transport closes on a missed reply;
  controls are hidden without `file_delete`, without `file_manage`, and in the drive list; the upload
  destination is frozen.
- **e2e with the test-harness agent (`backstage.spec.ts`):**
  - new folder, rename, upload-and-place, delete with the confirmation dialog;
  - a sensitive registry write now completes after confirmation;
  - against an agent that does not advertise `file_manage`, the controls are absent.
- **Windows 11 VM release check:**
  - the operations as SYSTEM on real Windows;
  - a guest-side screenshot showing only the pill and no per-action popup (the pill is excluded from
    the technician's capture, so the evidence must come from the guest side).

## 10. Filesystem and concurrency constraints

- The TOCTOU via a junction swap is replaced by the handle-relative walk with
  `OBJ_DONT_REPARSE` and held, non-delete-shared ancestors (§5).
- `PlaceUpload`'s destination is walked including its last component (§5).
- The protected-ancestor rename is closed by identity-based deny of roots, descendants and
  ancestors, and rename checks both operands (§5).
- Remote/network traversal: drive-type and syntax checks run before any filesystem access,
  and no reparse traversal is allowed at all (§5).
- Old agents and FIFO correlation: the `BackstageFeatures` advertisement, a reply for
  every frame, and close-on-timeout (§2).
- Upload provenance: placement by `transfer_id`, identity and digest re-check, single use
  (§4).
- `confirm` is documented as a client assertion with no evidential weight (§3).
- The `file_delete` widening is an explicit, documented decision (§4).
- Guest visibility is worded as "no per-action prompt", and presence loss now gates
  mutations (§1).
- Upload UX: a frozen destination, two-step reporting, a cross-volume preflight, and no
  auto-retry (§7).
- Audit: resolved operands, `file_place` with id and digest, the CP-first order and its
  rollback constraint, and qualified help text (§4, §6).

- Upload landing by name in a custom transfer root: a SYSTEM host now requires a
  trusted, anchored transfer root, and the whole upload lifecycle runs by handle (§5).
- A reopen after timeout could receive a stale reply: a timeout disables Under the Hood
  until the session reconnects (§2).
- Presence loss only gated new work: in-flight uploads are aborted and open shells are
  closed (§1).
- Failed-placement recovery pointed at a denied delete: added `DiscardUpload` (§4, §7).
- The confirmation retry re-resolved names: a token binds it to the resolved identities
  (§3).

- A custom transfer root could be a protected directory, and commit replaced files:
  the root must be dedicated (identity checks against the protected and system directories), and
  uploads never replace (unique landing names) (§5).
- Presence loss had no execution model: a `MutationGate` checked under its lock before each
  irreversible step, Backstage on a serial worker off the receive loop, and cancellable hashing (§1).
- A synchronous send failure left a queued resolver: the transport closes immediately
  (§2).

- A trusted custom root is not a dedicated one (DLL planting): a SYSTEM host accepts
  only the agent's own anchored `transfers` directory (§5).
- The gate's lock was held across filesystem calls: revocation is now an atomic flag
  loaded before each irreversible call, with no lock across I/O. The guarantee is stated exactly
  ("no new irreversible call after revocation; one already submitted may complete"), and the cleanup
  is queued to the worker (§1).

- **Chunk writes stalled the receive loop:** all transfer I/O moves to a bounded upload-writer
  thread (§1).
- **An atomic load cannot stop a call that is just being submitted:** the contract is restated in
  terms of admission, with the outstanding calls bounded at one per executor (§1).
- **A reusable boolean let aborted work resume:** a monotonic revocation generation, with work
  stamped at admission; reopening never revives old work (§1).

- A full writer queue could suspend the loop: the loop uses `try_send` and a full queue
  aborts the upload; it never awaits (§1).
- Gated cleanup could be stranded by a second loss: cleanup of an upload's own `.part`
  file is not admission-gated, and there is one terminal audit per transfer (§1).

- Overflow left queued writes valid and needed queue space for cleanup: each upload has a
  permanent cancel flag; the single writer owns all upload state, discovers cancellations itself and
  disposes by its own handle with no queue entry (§1).
- Abort raced commit: the writer arbitrates. Cancelled before commit admission →
  `Failed`; admitted → the commit's real result is the one terminal record (§1).

an idle writer could miss a cancellation. It now waits with a 250 ms
timeout and scans the flags on every wake; teardown is bounded (§1).

teardown cannot outwait a stalled call. Shutdown is bounded at 5 s,
with one "abandoned" chain record per unfinished upload; the writer keeps ownership and cleans up
when the call returns, logging the real outcome to the agent log (§1).

teardown did not revoke queued Backstage mutations. Every teardown path
now closes the gate and advances the generation first, before the pill goes away (§1).

## 11. Delivery (implementation notes, 2026-10-30)

docs/58 ships in two phases. Each phase is complete and safe on its own, and the console offers only
what the agent advertises.

**Phase A (agent 1.3.17), built:**

- **Audit kinds:** `file_create_dir`, `file_rename` and `file_place` in the CP verifier, deployed
  first (c6512452).
- **The dispatcher's file-op choke point:** CreateDirectory, RenamePath and DeletePath through
  `fileops::FileManager`, implemented on Windows by `fs_manage.rs`:
  - a handle-relative walk with no reparse traversal and held ancestors without share-delete;
  - identity-based protection of `C:\rmt-agent`, `C:\rmt-agent-bin`, the executable's directory and
    their ancestors;
  - sensitive-folder and top-of-drive confirmation;
  - deletes always confirmed;
  - renames never overwriting (FileRenameInformationEx without REPLACE_IF_EXISTS);
  - a bug fix in `anchor::rename_relative`, whose buffer was 22 bytes for a one-character name and
    failed STATUS_INFO_LENGTH_MISMATCH. The minimum is now sizeof(FILE_RENAME_INFORMATION).
- **Confirmation over the session channel:** the token of §3. It also fixes confirmable registry
  writes, which never completed before.
- **`MutationGate`:**
  - stamped at entry and re-checked by each commit at its irreversible call;
  - revoked on indicator loss (which also aborts in-flight uploads, and refuses new offers and
    downloads) and at teardown, before the guest window goes away;
  - reopened when the indicator returns.
- **Feature negotiation:** the console ASKS (`RequestBackstageFeatures`, sent when the session's
  control channel opens and again after `GrantInstalled`) and the agent answers
  (`BackstageFeatures`: `confirm`, `file_manage`). This corrects §2's "the agent sends it after
  GrantInstalled": an older console's `decodeControl` throws on an unknown variant, and it can
  arrive coalesced with other frames, so the agent never speaks first (the arming rule in
  `agent-core/src/control.rs`). An older agent drops the question as undecodable.
- **Every request gets one reply:** malformed and unknown requests get a `refused` envelope.
- **The console:**
  - a 60 s reply timeout and close-on-send-failure, both until reconnect;
  - New folder, Rename and Delete in the Under the Hood file browser, never in the drive list, with
    the §1 note;
  - the confirmation dialog shows the resolved path the agent reported.

In phase A, Backstage requests and upload chunks are still handled INLINE in the session loop, one
at a time, so an indicator-loss event cannot arrive while one is executing. The gate checks at entry
and at commit therefore suffice. The worker threads of §1 serve phase B, which adds long operations.

**Corrections to the text:**

- **No session shells exist.** The session host has no interactive shell (`Dispatcher::open_shell`
  is used only by the dev shell server), so "close open shells on presence loss" has nothing to act
  on yet. Whoever wires a shell into the session must revoke it with the gate.

**Phase B (later):** "Upload here", which needs:

- `PlaceUpload` / `DiscardUpload` (both refuse today with "placing uploads is not available on this
  agent version");
- the dedicated, identity-checked transfer root;
- handle-relative upload landing with unique names;
- the upload-writer and Backstage worker threads;
- per-upload cancel flags with timeout wake-ups;
- teardown bounding (§1, §5).

It will be advertised as a new feature (`file_place`), so no console offers it to a phase A agent.

## 12. Phase B plan ("Upload here", agent 1.3.18), with one simplification for review

Phase B builds §4's `PlaceUpload` / `DiscardUpload` and the upload pipeline of §1 and §5, with these
specifics:

1. **The transfer root is anchored.**
   - **Which hosts:** a host running as LocalSystem opens the transfer root ONLY as the agent's own
     `C:\rmt-agent\transfers`, through `anchor::Anchor::open_at`, which checks owner and DACL and
     that the parent cannot delete-child.
   - **The handle:** held for the whole session without delete sharing; staging is a validated child
     dir created with the protected SD.
   - **A configured `transfer_dir` naming anything else** disables uploads (and placement) for that
     session, with a logged warning. The installer writes the default, so no shipped machine changes.
   - **Not SYSTEM:** the attended support client and console dev runs keep today's per-run root and
     behaviour; they cannot place, and `file_place` is not advertised for them.
2. **Landing is handle-relative and never replaces.**
   - `.part` files are created relative to the held staging handle (`FILE_CREATE`, protected SD),
     written through that handle, and shared for read only while written.
   - Commit renames the `.part` by handle into the root with `ReplaceIfExists = false`. On a
     collision it lands as `name (2).ext` … `name (99).ext`, then refuses. The Ack carries the name
     actually used.
   - Abort and cleanup dispose by handle.
3. **Completed-upload records.** A successful commit records `transfer_id → (landing name, sha256,
   file identity)` in a per-session table shared with the file manager. `PlaceUpload` and
   `DiscardUpload` look the record up and open the landing file RELATIVE TO THE HELD ROOT HANDLE.
   They refuse unless it is a regular file, not a reparse point, and its identity matches the
   record. The record is consumed on success.
4. **No re-hash at placement (Codex-accepted simplification).**
   - **Why the re-hash existed:** §4's re-hash covered a custom `transfer_dir` that is not DACL-locked.
   - **Why it is now redundant:** item 1 removes custom roots on SYSTEM hosts. The landing file is
     created by SYSTEM, with an admin-only protected SD, in a root whose DACL grants no non-admin a
     mutating right, so only SYSTEM or an Administrator could change it before placement. The
     identity check still binds the placement to this session's committed file.
   - **What stays (Codex review of §12, r1):** the Backstage worker thread of §1. Even without
     hashing, a walk, rename or delete can stall on a slow or failing disk, and the session loop must
     keep processing indicator loss and teardown. So Backstage requests run on one serial worker,
     with the generation checks and teardown ownership of §1.
   - **The session loop keeps a read-only authorization view:** the grant plus the shared chain,
     for file-transfer gating, browse and feature checks. The dispatcher itself lives on the worker,
     so the loop never waits on a lock the worker could hold across a system call.
5. **The upload writer (§1) is built as designed.**
   - **One writer thread** owns every upload's state and all upload disk I/O. The loop forwards
     chunk and `Done` frames through a bounded channel of 64 with `try_send`, and never awaits it.
     Overflow sets the upload's permanent cancel flag, and the loop drops that upload's later frames.
   - **Cancellations and timing:** the writer discovers cancellations itself (`recv_timeout(250 ms)`
     and a flag scan on every wake), and checks admission before each write and the commit.
   - **Outcomes:** it decides commit against abort, and emits exactly one terminal ack plus one audit
     record per upload.
   - **Indicator loss** sets every live upload's flag. Teardown sets them, waits up to 5 s, then
     seals unfinished uploads as abandoned and leaves cleanup to the writer, which logs to the agent
     log.
   - **As built (Codex implementation review, r1):** cancelling and recording are separate. A
     cancel is a state (`LIVE` → a reason; none applies once the writer admits the commit as
     `COMMITTING`). The writer finishes an ending's disk work first and only then appends its record,
     through the session's ledger. Teardown revokes the gate and cancels uploads before its first
     await; after the 5 s wait it CLOSES the ledger and records "abandoned" for every upload still
     without a record, whatever its cancel reason or a commit under way. After that the writer never
     appends: a late outcome goes to the agent log only. A repeated Offer id is refused without
     touching the running upload, and installing a grant never waits on the writer's queue.
   - **As built (r2):** the writer scans cancellations on every wake BEFORE handling the item that
     woke it. The anchored root's `.rmt-staging` is a validated anchor child (a pre-existing one that
     a non-admin can write is refused), and each `.part` there gets the protected admin-only SD
     explicitly, so an inherit-only grant on staging is never inherited. A transfer id can start
     once per session, so a completed record is never overwritten by a later upload. Codex
     accepted the threads (A1 r3), the root and placement (A2 r3) and the console (B r2).
6. **Placement rules:**
   - **Destination:** `dest_dir` is walked in full (§5) and must be on the transfer root's volume.
     A different drive is refused before any change, and the console preflights it.
   - **Guards:** the guard rules are §5's: deny protected and new-protected names; confirm sensitive
     folders and the top of a drive.
   - **Audit:** `file_place { transfer_id, sha256 (the committed digest), to (resolved) }`.
   - **Discard:** `DiscardUpload` audits `file_delete` with the resolved landing path.
7. **Advertisement:** `file_place` only when the session has an anchored root AND the installed grant
   holds `file_delete`.
8. **Console:** "Upload here" in the Under the Hood browser.
   - The destination is frozen when the upload starts.
   - Uploads go through the existing transfer channel.
   - Each file reports two steps, "Uploaded" and "Placed in <dest>".
   - On a failed placement it offers Discard.
