# Shared Toolbox — v1 design

Status: v2 after Codex design review v1 (repair: immutable scope, versioning, run-request audit, cmd limits, transactions) (2026-10-16). Parity item docs/01 "Shared Toolbox" (P1, absent).

## Goal

A technician keeps a library of scripts and runs any of them on the machine they are connected to, in
one click, with the result shown in the session. Scripts are either the tenant's **shared** items
(managed by admins) or the technician's **personal** items. This is ScreenConnect's "Toolbox", minus
binaries for now.

## Scope

**In v1**
- Script items only: PowerShell (multi-line) and cmd (single line).
- Two scopes: **shared** (tenant-wide, everyone who can start sessions sees them) and **personal**
  (visible to and editable by its owner only).
- Run **inside a live session** on that session's machine, as SYSTEM or as the logged-in user, with the
  captured result shown in the viewer. Every run is audited in the management audit chain.
- Console: a Toolbox area (list/create/edit/delete) and an in-session Toolbox menu (pick → confirm → run).

**Not in v1 (later, each its own design)**
- Executables / installers (needs blob storage + transfer + integrity pinning).
- Running on machines **without** a live session, and bulk runs across many machines (needs an
  agent-side "job" path that does not exist; today every execution rides a session's control channel).
- Running with supplied credentials (agent `Identity::Credential` is `unimplemented!()`).
- Approval workflows, script signing, parameters/prompts.

## Why no agent change

Execution reuses the shipped command bar path end to end: `ControlMessage::RunCommand{command, shell,
as_user}` → `CommandResult{exit_code, stdout, stderr, truncated, timed_out}` (agent-core control.rs;
actuator crates/agent-windows/src/command_run.rs: CreateProcessW as SYSTEM or CreateProcessAsUserW with
the user's BASE token, hidden, stdin NUL, 64 KiB per stream, 30 s wall clock, Job-Object tree kill). It
is available to any controller with a non-view-only session — the toolbox adds **no execution
capability** a session holder does not already have; it adds storage, sharing, and audit.

PowerShell's agent invocation is `powershell.exe -NoProfile -NonInteractive -Command <command>`. Rather
than depend on how Windows argument parsing and PowerShell treat quotes, newlines and non-ASCII in a raw
script, the console sends a fixed, quote-free wrapper (an encoding choice):

    & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64>'))))

where `<b64>` is the item body's UTF-8 bytes. Windows' command-line limit is 32 767 UTF-16 units; the
wrapper plus `ceil(n/3)*4` base64 characters must fit, so the **body is limited to 16 384 UTF-8 bytes**
(validated server-side at save, ~21.9 K base64 + ~150 wrapper). Execution policy is not a security
boundary and an endpoint's policy may still refuse; the VM harness verifies the full serialization.

cmd items are sent as-is. The agent's line is `"<SystemRoot>\System32\cmd.exe" /C <command>` and cmd.exe
caps a whole line at 8 191 characters. The body limit is therefore **7 800 UTF-16 code units** (8 191
minus the prefix with a SystemRoot up to MAX_PATH), counted in UTF-16 (non-BMP = 2 units), single line
(no CR/LF), no U+0000. All bodies must be valid UTF-8 (strict decode; invalid input is 400, never
replaced). PowerShell bodies also reject U+0000.

The 30 s timeout and 64 KiB output caps apply unchanged; the UI says so on the item editor.

## Data model (migration 0056_toolbox.sql)

    CREATE TABLE toolbox_item (
        id            uuid PRIMARY KEY,
        tenant_id     uuid NOT NULL REFERENCES tenant(id),
        owner_user_id uuid NULL,            -- NULL = shared; else personal to this user
        name          text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
        description   text NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
        shell         text NOT NULL CHECK (shell IN ('powershell','cmd')),
        run_as        text NOT NULL CHECK (run_as IN ('system','user')),
        body          text NOT NULL,        -- shape rules in Go; byte backstop below, per shell
        CHECK ((shell = 'powershell' AND octet_length(body) <= 16384)
            OR (shell = 'cmd'        AND octet_length(body) <= 31200)),  -- 7 800 UTF-16 units x <= 4 UTF-8 bytes
        body_sha256   text NOT NULL,        -- hex of sha256(UTF-8 body), recomputed by the store
        version       bigint NOT NULL DEFAULT 1,  -- +1 on EVERY successful update (any field)
        created_by    uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
        updated_by    uuid NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(),
        FOREIGN KEY (tenant_id, owner_user_id) REFERENCES app_user(tenant_id, id) ON DELETE CASCADE
    );
    CREATE UNIQUE INDEX toolbox_item_name ON toolbox_item (tenant_id, coalesce(owner_user_id, '00000000-0000-0000-0000-000000000000'), lower(name));

- RLS: ENABLE + FORCE, the standard `tenant_isolation` policy on `app.current_tenant` (no
  `missing_ok`), grants to rmt_app. Personal visibility is NOT an RLS concern (RLS is per tenant); it is
  enforced in every store query with `owner_user_id IS NULL OR owner_user_id = $caller`, and tested.
- **Scope and owner are immutable** after creation. Creating a shared item needs `manage_toolbox`; a
  personal item's owner is always the authenticated caller (never taken from the request). There is no
  way to move an item between scopes or owners in v1: copy it instead (create + delete).
- The composite FK (tenant_id, owner_user_id) → app_user(tenant_id, id) pins a personal item's owner to
  the same tenant (the composite-FK lesson: a plain FK to a global PK bypasses RLS on write). Requires
  app_user to have a UNIQUE (tenant_id, id); add it in 0056 if absent. A deleted user's personal items
  go with them.

## Authorization

New capability `manage_toolbox` (presets: Owner, Admin). Everything else rides existing capabilities.

| Action | Requirement |
|---|---|
| List (shared + own personal) | `start_session` in ANY group (no machine scope — items are not machine-bound) |
| Create/edit/delete **personal** | `start_session`; only the owner, enforced in the WHERE clause |
| Create/edit/delete **shared** | `manage_toolbox` |
| Edit/delete **another user's personal** item | never (it is invisible: 404) |
| Run | the run endpoint below |

Custom roles store capability strings (0001 `capabilities text[]`); a new key needs no migration of
existing rows (absent = not granted). API tokens never get `manage_toolbox` implicitly.

## Run flow (the audit is authoritative, not the browser)

1. Console: `POST /toolbox/{id}/runs {session_id, expected_version}`. The control plane authorizes and
   records a **run request**; it cannot know whether the browser delivers the command or what the agent
   does with it (the browser could equally type anything into the command bar). The event says so.
2. Control plane, on the request's pinned connection:
   - the session exists in the caller's tenant, was started by the caller (`technician_id`), is not
     ended, and its machine is not quarantined/out of service;
   - the caller still holds `start_session` for the session's machine group (`RequireMachine`), and
     every other condition a lease renewal requires (handleRenewSessionPolicy's authorization checks,
     factored into one function both call). The control plane stores no lease timestamps (leases are
     signed policies the agent holds), so "current lease" means "a renewal would be granted now"; the
     run does NOT extend or mint a lease. Delivery-time enforcement stays with the agent's policy;
   - the access level the control plane would sign for this session NOW is not view-only. It is not
     stored on session_record; it is computed per mint (group policy enforce_view_only etc.), exactly as
     handleRenewSessionPolicy computes it for each lease renewal, so the run endpoint calls the same
     function. (A view-only session's agent refuses RunCommand anyway, host.rs "view-only mode: running
     a command is not allowed"; refusing here keeps the audit honest. An operator's own in-session
     view-only toggle is client-side and not visible here; the agent still refuses in that case.);
   - the item is visible to the caller and `version == expected_version` (409 otherwise: the item
     changed after the operator looked at it);
   - reads the item ONCE (a single row snapshot) and derives both the audit fields and the returned
     command from that snapshot; it never re-reads after auditing;
   - appends `toolbox.run_requested` to the management audit chain: a new request id (uuid), the actor
     (user id + email), item id, name, scope, version, body_sha256, shell, run_as, session id, machine
     id, `outcome: "unknown"`. The response is returned only after that transaction COMMITS; if the
     append fails the request is refused (500).
3. Response: `{request_id, shell, run_as, command}` where `command` is the exact text to send (the PowerShell
   wrapper with the body, or the cmd line). The console sends exactly that as `RunCommand` and shows the
   `CommandResult`.

The browser could send a different command; it could do that with the command bar anyway (same session
authority). The audit records what the operator asked the toolbox to run; the command bar's own
behaviour is unchanged. Output is not stored server-side in v1 (it may contain secrets; the session
recording, if on, shows the run).

## Management audit events

`toolbox.item.create|update|delete` with item id, scope, name, version, body_sha256 (never the body).
`toolbox.run_requested` as above. Each create/update/delete and its audit append commit in ONE
transaction on the request's pinned connection; update/delete compare `version` in the same SQL
statement (`... WHERE id=$1 AND version=$2 RETURNING ...`; 0 rows → 409 if the row exists for the
caller, else 404). Agent acknowledgements tied to the request id are a later, separate change (only
needed if authoritative execution records are wanted).

## API

    GET    /toolbox                      -> {items: [{id,name,description,scope,shell,run_as,version,body_sha256,body,updated_at,updated_by_email,mine}]}
    POST   /toolbox                      {name,description,scope:"shared"|"personal",shell,run_as,body} -> 201 {item}
    PUT    /toolbox/{id}                 {...same, expected_version}  -> 200 {item} | 409 version | 404
    DELETE /toolbox/{id}?expected_version=N -> 204 | 409 | 404
    POST   /toolbox/{id}/runs            {session_id, expected_version} -> 200 {shell,run_as,command}

Request bodies for these routes are bounded at 128 KiB: the worst JSON escaping is 6 bytes per UTF-16 unit (7 800 x 6 = 46 800 for cmd) or per byte for control characters (16 384 x 6 = 98 304 for PowerShell). 404 for an item the
caller cannot see (no existence oracle for other users' personal items). Validation errors 400.

## Console

- **Toolbox area** (tab "Toolbox", shown to anyone with `start_session`): table (name, scope, shell, run
  as, updated), search, create/edit form with a monospace body editor, size counter against the limit,
  the 30 s / 64 KiB note, delete with confirm. Shared items editable only with `manage_toolbox` (server
  decides; UI hides controls on 403-known capability from the existing grant info).
- **In session**: a "Toolbox" entry in the session's tools menu: searchable list → item preview (body,
  run as) → "Run on <machine>" → result panel (exit code, stdout, stderr, truncated/timed-out badges).
  Disabled in view-only sessions. One run at a time (the agent refuses a second concurrent RunCommand).

## Tests

- pg: RLS isolation across tenants; personal items invisible/unmodifiable to another user of the same
  tenant (list, PUT, DELETE, run all 404); composite FK refuses a cross-tenant owner; size limits
  (16384 bytes OK, 16385 refused; cmd newline refused); version conflicts; run refused for another
  user's session, an ended session, a quarantined machine, a view-only session, a group the caller lost;
  run audit row written with body_sha256 and refused when the audit append fails.
- Go + pg: save/update at the cmd boundary with three-byte BMP characters (7 800 x 3 = 23 400 bytes)
  and with non-BMP characters (3 900 x 4 bytes = 7 800 UTF-16 units), both accepted end to end, one unit
  over refused with 400 (never a database error).
- Go unit: UTF-8 strictness (invalid sequences 400), U+0000 refused, cmd limit counted in UTF-16 with
  non-BMP characters at the 7 800 boundary.
- Go unit: the PowerShell wrapper round-trips arbitrary UTF-8 (quotes, `$`, newlines, non-ASCII) and its
  length bound holds at the 16384-byte limit (≤ 32 767 UTF-16 units including the exe path).
- Agent (existing VM harness, no code change): a 16 384-byte multi-line PowerShell script with
  quotes, `$`, non-BMP characters, and a 7 800-unit cmd line with non-BMP characters, run through
  RunCommand as SYSTEM and as user, returning the expected output byte for byte.
- Console: vitest for the API client; mocked Playwright for the area and the in-session run (including
  409 on a changed item, disabled in view-only).

## Questions for the reviewer

1. Is "no new execution capability, so no new agent authorization" sound, given RunCommand is already
   available to any non-view-only controller?
2. Is the run endpoint's check set complete (session ownership, live, machine state, group authority,
   access level, version)? Should a run also require the session's lease to be current?
3. Personal-scope enforcement in queries (not RLS): acceptable, given the tests?
4. Anything wrong with the wrapper (injection via the base64 literal is impossible since it is
   [A-Za-z0-9+/=]; execution policy does not apply to -Command scriptblocks)?
