# docs/68 - Private download and adoption report

Status: stages 1-4 of section 10 (parser, ingest, migration 0078, the two routes) are shipped and deployed; the feature ships OFF (opt-in). The console UI (stage 5: the Reach tab and the Adoption card) is shipped too; the live canary (stage 6) is not done; see "As built" at the end. **Decided:** unique-ish per-day counts WANTED (section 5 salt machinery is in scope); raw access.log retention stays as is (size cap only, no age cron; section 9 item 4 is dropped); GitHub activity parked ("Not now"). Audience: the operator and deployers.

## 1. Goal and non-goals

The goal is to know whether anyone is using DeskRally and whether that is growing. The report must be private and count only what we can defend.

Non-goals:
- No third-party analytics, pixels, or cookies on the download path.
- No per-visitor profile and no stored IPs.
- No tracking of what anyone does after they download.

## 2. Audience

| Viewer | Sees | Source |
|---|---|---|
| Platform operator (MFA-gated, docs/55 model) | Cross-tenant download counts and aggregate adoption | New `cp_platform_*` aggregate functions |
| Tenant Owner (`manage_tenant`) | Only their own tenant's adoption: codes issued and redeemed, new devices, active devices, agent-version spread | Existing tables under RLS |
| Everyone else | Nothing | n/a |

Downloads are anonymous and belong to no tenant. They are platform-level only. Tenant Owners never see download counts.

## 3. What is counted, and its honest label

Each number carries its label in the UI and in the API field name. We never call a request a "download".

| Label | Definition | How derived | Caveat shown in UI |
|---|---|---|---|
| Download requests | GET with status 200 or 206 on a human artifact | Caddy log, classified by URI | Includes bots, retries, and previews |
| Completed (approx.) | GET, status 200, `size` >= artifact size minus 1 KiB | Log `size` against the known artifact size | 206 resumes are not stitched together |
| Unique-ish clients / day (mean) | Distinct salted-hash of (IP, User-Agent) per day, per artifact | See section 5 | Per day only. NAT merges people and mobile IPs split them |
| Registrations (real adoption; the UI's Adoption card shows them as new devices per week) | `machine.enrolled_at` per tenant, per day | Postgres | The true "installed and enrolled" signal |
| Attended sessions | `attended_session` funnel: issued, redeemed, consented, active | Postgres | Proves the support client actually ran |
| Updates | Update-feed manifest GETs and `DeskRallyAgent.msi` payload GETs | Log, classified by URI | Machine traffic. It never counts as a download |

Human artifacts, taken from the Caddyfile:
- `/download/DeskRallySupport.exe`
- `/download/server/deskrally-server-*.tar.gz`
- `/download/agent/new-msi-provisioning.ps1`

Sidecars (`*.sha256.txt`) and `/download/server/latest.json` go in an "other" bucket.

Update traffic, kept out of downloads:
- `/download/agent/v2/*/manifest.json`
- `/download/client/manifest.json`
- `/download/agent/*/manifest.json`
- `/download/agent/releases/*/*` and `/download/client/releases/*`

All other paths, including 404s, go to `other` or `noise`. Only the noise total is kept, to show scanner volume.

Classification is by URI only. The agent sends no custom User-Agent, so the User-Agent cannot be used as a marker.

Claims we will not make:
- "Unique users" or "installs" from the log.
- Any cross-day uniqueness.
- A mapping from a download to a registration. There is no identifier linking them, and we will not add one.

## 4. Pipeline options

**A. Sidecar or cron parses `access.log` into daily aggregates in Postgres.** The existing Caddy JSON log is the only source. Nothing changes on the request path.

**B. Control plane tails the log file.** This puts a long-lived file reader in the control plane. The control plane would need read access to the caddydata volume, which widens its blast radius.

**C. Control-plane-served download endpoint.** This puts the app in the download path. A control-plane outage would then break downloads and the agent update feed. It also adds load and attack surface to the most exposed route. It would count precisely, but at the cost of availability.

**Recommendation: A.**
- It adds no new runtime dependency to downloads. Caddy keeps serving static files.
- The privacy boundary is a single small job. It reads raw lines, writes aggregates, and discards the lines.
- It is testable offline with fixture log files.
- The control plane never mounts the log, and the DB role for the job can write only the aggregate tables.
- Limit: the log rolls by size (20 MiB x 10), not age. The job must run often enough that a roll cannot lose a day. Run it hourly and keep a byte-offset and inode cursor per file. Missed windows are shown as gaps, not zeros.

## 5. Privacy

- The DB stores only `(day, artifact_class, artifact, status_class, requests, completed, unique_clients, bytes)`. It holds no IPs, no User-Agents, and no per-request rows.
- Unique-ish counting, if enabled:
  - Compute `HMAC-SHA256(daily_salt, remote_ip || '|' || user_agent)` in memory.
  - Keep a set only within the job process for that UTC day, and write only the cardinality.
  - Hold the salt in memory and in an `0600` file under tmpfs. Never write it to the DB, a backup, or a log.
  - Generate a fresh random salt at each UTC midnight and overwrite the old one. After that, the previous day's hashes cannot be recomputed or linked.
  - If the job restarts mid-day, it reloads that day's salt from the tmpfs file. If the file is gone, it starts a new salt and the day's unique count is flagged "partial".
- Raw `access.log` stays as the forensics and fail2ban source (docs/24). Today its retention is only the size cap. Recommended: shorten and document it, for example a 14-day cap enforced by a cron `find -mtime`. Decided: retention stays as is (size cap only; section 10).
- Aggregate retention: 25 months, then dropped. Aggregates are not personal data, but they are bounded anyway.
- No third-party analytics anywhere. Add one line to the public site and `docs/guides/server-deployment.md`: "We count downloads from server logs in aggregate. We store no IP addresses in our reports and use no third-party analytics."
- There is no existing privacy promise in the repo. This design sets one, so wording on the public site should match it.

## 6. Data model (migration 0078+)

- `download_daily(day date, artifact text, class text, requests int, completed int, uniq int null, bytes bigint, partial bool, PRIMARY KEY (day, artifact, class))`. This table is not tenant-scoped.
- `download_ingest_cursor(file_id text PRIMARY KEY, inode text, offset bigint, updated_at timestamptz)`.
- Both tables live outside tenant RLS. The app role `rmt_app` gets no direct SELECT. Reads go only through `SECURITY DEFINER` functions, owned per the 0076 pattern. The function `cp_platform_downloads(from, to)` calls `cp_platform_check` first (MFA within 12 h).
- Ingest runs as its own role with INSERT/UPDATE on these two tables only.
- The tenant adoption function is `cp_tenant_adoption(from, to)`. It uses ordinary RLS-scoped queries and returns counts only.

## 7. UI

- Platform: a new tab in `PlatformPanel.tsx` called "Reach". It has a table (artifact, requests, completed, unique-ish, updates) for 7, 30, and 90 days, with a sparkline per row. A footer prints the section 3 caveats verbatim.
- Tenant Owner: an "Adoption" card in tenant settings. It shows new devices per week, active devices in the last 30 days, the attended-session funnel, and the agent-version distribution.
- The UI offers no export of raw rows, no drill-down below day level, and no IP search.

## 8. Security

- The platform route is `GET /platform/reach`. It has the same gate as `/platform/tenants`: an interactive session, MFA freshness, and an API token can never qualify.
- The tenant route is `GET /adoption`. It requires `manage_tenant`, and RLS supplies the tenant scoping.
- Reads of the platform report are audited, as lifecycle changes already are.
- The ingest job has no network listener and no shell-out.
- `reach-ingest` mounts the `caddydata` volume read-only as uid 0, because Caddy writes `access.log` 0600 as root. That volume also holds Caddy's TLS private keys and ACME account keys under `/data/caddy`.
  - **The keys are masked:** an empty mode-0000 tmpfs is mounted over `/data/caddy` in that container. Without CAP_SYS_ADMIN the process cannot unmount it.
  - **Verified** on a real deployment host, in a throwaway container with the same settings: 0 files were visible under `/data/caddy`, and all `access*.log*` files were readable.
  - **The mount point must already exist,** so the service depends on caddy having started.
  - **Residual risk:** the parser still runs as uid 0, with `cap_drop: ALL`, no listener, a read-only root filesystem and no-new-privileges.
  - **The stronger fix,** a second Caddy logger writing to its own volume so the ingest can run as non-root, needs a Caddyfile change and a caddy recreate. It is left for a deliberate later change.
- Log lines are untrusted. The parser treats the URI as data, bounds its length, and never uses the URI itself as a path or a SQL fragment. The one filesystem use (the completed-download size check) takes the artifact NAME that a fixed regex produced, joins it under the single directory the operator configured (`REACH_ARTIFACT_DIR`) and stats it read-only; the join is refused unless the name is a local relative path and the result stays inside that directory (tested with `..`, percent-encoded, absolute and drive forms).

## 9. What the deployment must change

1. Mount `deploy_caddydata` read-only into a new `reach-ingest` service in the prod compose. Do not mount it into the control plane.
2. Keep Caddy `format json`. If deployment adds an `include` filter, it must keep `ts`, `remote_ip`, `uri`, `method`, `status`, `size`, and `request.headers.User-Agent`.
3. Add a tmpfs mount for the salt. Add a DB role and its credentials, then apply the migration with `--allow-migrations`.
4. (Dropped: no retention cron on `access.log`; retention stays as is, size cap only.)
5. Do not add `skip_log` for any `/download/*` path.

## 10. Build plan

| Stage | Work | Tests |
|---|---|---|
| 1 | Log parser and classifier (a pure function). It handles roll-over, partial lines, and cursor resume. | Table-driven tests on fixture logs: human vs update vs noise, 206 vs 200, HEAD, a truncated `size`. A mutation test on the classifier. |
| 2 | Migration, aggregate writer, and the salted-hash uniqueness | A test that dumps the DB and asserts no IP or User-Agent string appears. Salt rotation unlinks the prior day. A restart mid-day marks the day "partial". |
| 3 | `cp_platform_downloads` and the `/platform/reach` route | DB-verified: non-operator is refused, stale MFA is refused, an API token is refused. An RLS test with a second tenant. |
| 4 | `cp_tenant_adoption` and the `/adoption` route | Tenant A never sees tenant B counts. Counts match seeded rows. |
| 5 | UI tabs and caveat text | A Playwright spec for both views. A spec that the word "downloads" never labels raw requests. |
| 6 | Deployment change and a canary run on the live log | Compare the parser's output to a hand count of one real day. |

Decisions (resolved):
- Raw log retention in days: left as is (size cap only).
- Whether unique-ish counts are wanted at all: yes. Dropping them would have removed the salt machinery entirely.

## 11. GitHub activity / pull requests (parked)

"GitHub activity" could mean one of these:
1. **Repo traffic on the public GitHub repo**: clones, views, stars, and release-asset download counts. GitHub shows these to the repo owner, and release-asset counts are the closest thing to downloads if releases are published there. This needs no code from us.
2. **Pull requests and commit activity on the project's GitHub repository**: contributor and PR flow for the open-source project.
3. **Developer-side activity**: the project's own contributors' commit and PR history.

Which of (a) people downloading or cloning the public code, (b) outside contributors opening pull requests, or (c) the project's own commit and PR history is wanted was left open; this item is parked.

## 12. As built (stages 1-4, server side)

Shipped and deployed, off by default; not yet run in a live canary against a real log. Where it differs from the design above:

* **Package `control-plane/reach/`**: `ParseLine` (Caddy JSON; lines over 32 KiB, a URI over 2 KiB or a User-Agent over 512 bytes are bounded,
  malformed lines are counted and skipped), `Classify` (method + URI + status only, matching the Caddyfile's own `/download` patterns, no
  decoding of the URI; HEAD, 404, 3xx and 416 on an artifact go to noise; a 304 counts for the update and other buckets only), `Completed`.
  `cmd/reachingest` is the process. Classification buckets as in section 3; the human artifact label is its path under `/download/`, the update
  and other buckets use fixed labels (`agent-manifest`, `agent-payload`, `client-manifest`, `client-payload`, `sidecar`, `server-latest`).
* **Completed downloads**: the ingest mounts the artifact directory read-only (`REACH_ARTIFACT_DIR`) and compares each 200's size with the file's
  size *now*. A size it cannot read stores `completed` as NULL (unknown), not 0. A log line about an older build of the same file name is
  judged against the current build: the caveat the report prints.
* **A long-running loop, not cron**: the unique-ish set must live between passes. Runs at start and every `REACH_INTERVAL` (default 1h).
* **Cursors identify a log SEGMENT by a hash of its first line's `ts` text (a server timestamp, nothing a client sent)**, not an inode or a name. Caddy renames `access.log` to
  `access-<time>.log` and gzips it (a new inode, a new name, the same content); that timestamp is stable through both,
  and the byte offset is into the *decompressed* stream. Aggregates and the cursor are committed in one transaction, so a crash neither loses
  nor double-counts a line, and the unique-ish set is idempotent under a re-read. `download_ingest_cursor` therefore has `file_id`, `last_name`
  (informational), `byte_offset` and `updated_at`, not an `inode` column. A cursor is pruned only when its segment is no longer on disk
  AND it is 60 days stale, and never when the log directory looks empty.
* **Salt**: held in memory and in a 0600 file on a tmpfs, rotated when the data's UTC day advances (and idly at midnight), the old file
  overwritten in place. A reloaded salt (restart mid-day) or a missing/garbled salt file marks that day's unique-ish figure **partial**; a
  line from a day older than the salt (a backlog) adds to the counts but has no unique-ish figure and is flagged. A set is capped at 500,000
  clients per artifact and day (flagged past it). The stored `uniq` only ever rises (`GREATEST`), so a restart's smaller set cannot lower it.
* **Migration 0078**: `download_daily` and `download_ingest_cursor` (no column can hold an address, a User-Agent or a client hash; `file_id` is a hash of a server timestamp), role
  `rmt_reach_ingest` (NOLOGIN; the deployment adds LOGIN and a password, docs/20 section 16) with SELECT/INSERT/UPDATE/DELETE on those two tables
  only (SELECT because the upsert adds to the stored count; DELETE for retention, 25 months), `rmt_app` has NO privilege on either table, and
  the read is `cp_platform_downloads(user, session, from, to)`: `cp_platform_check` (12 h MFA) first, a range of at most 400 days, owned by
  `rmt_definer` (which gained `SELECT ON download_daily`; `expectedDefinerPrivileges` lists it).
* **Routes**: `GET /platform/reach?from=&to=` (default last 30 days, at most 400) answers rows plus the section 3 caveats; field names are
  `requests`, `completed_approx`, `unique_ish_clients`, `unique_ish_partial`. Audited as `platform.reach.read` on the platform chain in the same
  transaction as the read, so a denied caller leaves no event. `GET /adoption?from=&to=` (CapManageTenant) answers, for the caller's own tenant
  under RLS: `new_devices_per_week` (machine `enrolled_at`, Monday weeks UTC, guest/ephemeral machines excluded), `active_devices_30d`
  (`last_seen` within 30 days, not retired; since migration 0079 the control plane's presence sweep stamps `last_seen` every
  2 minutes for every connected device, so this is a liveness count. Before 0079 it was stamped only when a console listed the
  machine, so days before that deploy may undercount, and the card's tooltip says so), `attended_funnel` (issued, redeemed, consented, active, for sessions created in the range) and
  `agent_versions` (the semver part of `agent_version`, retired and guest machines excluded, `unknown` for none reported). The function
  `cp_tenant_adoption` of section 6 was not needed: the counts are plain RLS-scoped queries in Go (`PgAdoptionStore`).
* **Compose**: service `reach-ingest` under the profile `reach` (docs/20 section 16), `caddydata` mounted read-only into it only, a tmpfs for the
  salt, its own DSN variable, empty by default. The control plane does not mount the log. The image now also contains `/usr/local/bin/reachingest`.
* **Not done**: the Reach tab and the Adoption card (stage 5), the Playwright specs, and the canary comparison against a hand count of one real
  day (stage 6). Migration 0078 is applied by the normal migration step; the operator still has to set the role's password and start the profile.

### Review fixes (first pass)
* Reach tab renders for any operator (not only a fresh factor), so its own 403 handling and code prompt take over; header labels are the shipped ones listed in section 3.

* A corrupt or truncated rolled segment is logged by name (`read error in <name> after N bytes`), counted in `Stats.ReadErrors` and the lines read before the fault are still committed. Salt file mode is set before the key is written; the old key is zeroed in memory on rotation. Semver digit runs are bounded to 6 digits so an artifact label cannot exceed the column's 128-character check.
* Adoption date ranges are pinned to UTC like the weekly buckets.
* What a routine deploy changes, exactly: migration 0078 (two empty tables, a role, a function), a second binary in the control plane image, `GET /platform/reach` (operator gate) and `GET /adoption` (live at once for tenant Owners, with the Adoption card in the console's Security view and the Reach tab on the Platform page). Nothing about existing flows changes; the `reach-ingest` service itself does not start without `--profile reach`.

### Independent review fixes (second pass)

An independent review of `control-plane/reach` and `cmd/reachingest` asked for repairs. Fixed:

* **A roll between discovery and read (HIGH).** The ingest used to identify `access.log` at discovery and then reopen it by path, so a roll in between paired the replacement file's bytes with the old segment's id and offset (new requests skipped, the rolled file later recounted). A segment is now opened ONCE; its id is computed from that same handle (a peek that consumes nothing) and the cursor is looked up by that id. A candidate that vanished, was renamed or compressed is skipped and found again next pass under its new name; an id is consumed at most once per pass. Test: `TestRollBetweenDiscoveryAndReadIsReadAsTheFileItIsAndCountsEachLineOnce` (a seam rolls the file after discovery).
* **Work budgets (MEDIUM).** `MaxSegmentBytes` (default 512 MiB decompressed; Caddy rolls at 20 MiB) bounds one segment including the re-read of its counted prefix; a segment over it is logged by NAME, counted in `Stats.Capped`, its lines before the cap are kept, and its cursor is pinned at the cap so it is never read again (the rest of that segment is not counted). `MaxPassBytes` (default 2 GiB of NEW bytes) stops a pass cleanly (`Stats.BudgetStopped`) and it resumes next pass; the re-read of already-counted prefixes (a gzip cannot seek) has its own `MaxSkipBytes` (default 8 GiB), so the prefix cost cannot starve progress. The context is checked inside every read, not only between batches.
* **Process-wide bounds (MEDIUM).** `MaxTotalUniq` (default 2,000,000 hashes) and `MaxArtifacts` (default 256 client sets and size-cache entries) join the per-artifact `MaxUniq`. Past either, the affected rows are partial and carry no figure; request counts are never dropped. Past the size-cache bound the size is "unknown" (completed stays NULL) without a stat.
* **Salt hygiene (MEDIUM).** Expiry no longer depends on a pass succeeding (a deferred rotation runs however the pass ends), a salt file left from an earlier day is replaced at startup, and a write failure falls back to erasing the file. If an expired key can be neither overwritten nor removed (or a new key cannot be made) the ingest FAILS CLOSED: no unique-ish counting, the rows are partial, a loud log line says so, and every pass retries.
* **`file_id` carried personal data (doc claim).** It was SHA-256 of the whole first line, which contains the client IP. It is now derived from the first line's raw `ts` field text ONLY (not the IP, User-Agent, URI or the line length, all of which a client controls); the migration's 32-hex CHECK still holds. Test: ids of two first lines that differ in everything but `ts` are equal. The earlier statement "no hash reaches the database" is corrected above: the only hash stored is this cursor id, and it is a hash of a server timestamp.
* **Filesystem wording (doc claim).** See section 8: the URI is never a path, but a regex-validated artifact name is joined under `REACH_ARTIFACT_DIR`; `artifactPath` refuses non-local names and verifies the result stays inside the directory.
* **Logged errors.** The ingest logs file names, byte counts and Go/pgx error text only. SQL arguments are day, artifact label, class, counts and the cursor's id, name and offset, so a database error cannot carry an IP, User-Agent or client hash; `TestLoggedTextNeverCarriesClientData` runs a read error, a failed commit and a capped segment over hostile lines and asserts none appears in the log.

### Independent review fixes (third pass)

A further independent review of `control-plane/reach` followed. Fixed or answered:

* **Skip budget restarted every pass (MEDIUM).** Segments are read oldest first and the budget for re-reading already-counted prefixes restarted each pass, so once the counted history alone used it up, every pass repeated that work and the newest segment stayed unread. Progress is now guaranteed: `download_ingest_cursor` has a `complete boolean NOT NULL DEFAULT false` column (migration 0078, `Cursor.Complete` in both stores). A ROLLED (non-active) segment read to its clean end is marked complete in the same transaction as its last aggregates, and so is one given up on at the size cap; a complete segment is recognised from the id discovery already computed and is not opened again (`Stats.Skipped`), so it costs no budget at all. An uncompressed segment that is not complete is SEEKED to its cursor instead of read through, so only a partly-read `.log.gz` still pays a prefix re-read. The active file is never marked complete, and a read error or a budget stop is not an end. Tests: `TestRolledHistoryExceedingTheSkipBudgetDoesNotStarveTheNewestSegment`, `TestUncompleteCursorsAreSeekedNotReReadAndTheNewestIsReachedInBoundedPasses`, `TestCappedRolledSegmentIsCompleteAndTheActiveFileNeverIs` (history several times the skip budget, the newest segment is read within a bounded number of passes, nothing is counted twice).
* **gzip header before the limiting reader (MEDIUM; the unbounded claim does not hold).** In the installed toolchain (go1.26.9) `compress/gzip/gunzip.go` bounds the header itself: `readString` (name and comment) returns `ErrHeader` once `i >= len(z.buf)` and `buf` is `[512]byte` (lines 141-147 and 80), and the extra field is `make([]byte, le.Uint16(...))`, so at most 65535 bytes (line 203). A header can therefore cost about 66 KiB, not unbounded input. It was still read outside the pass's accounting and cancellation, so the file is now wrapped in a ctx-aware, byte-capped reader BEFORE `gzip.NewReader` (cap: the segment cap in a pass, 1 MiB in discovery), the context is checked before any file or gzip work, and discovery (`ListSegments`) takes the context. Test: `TestOpenHonoursCancellationBeforeAnyReadAndChargesGzipHeaderBytes`.
* **`SaltFile.Exists` treated every Lstat error as absence (MEDIUM).** A permission or I/O error could clear `diskStale` and resume hashing while an expired key might remain. Only `errors.Is(err, os.ErrNotExist)` now means absent; any other error means possibly present and the ingest stays fail closed. Tests: `TestSaltFileExistsOnlyAbsentOnNotExist`, `TestUnreadableSaltPathStaysFailClosedWhenTheKeyCannotBeErased`.
* **Cursor id format (HIGH, not applicable).** The review asked for the id to change again (first-line hash to timestamp hash) without orphaning persisted cursors. The ingest ships off, so no persisted cursor is expected to exist. The id format (SHA-256 prefix of `deskrally-reach-segment-v2` plus the first line's raw `ts` text) is v1-of-record as first shipped; any future change to the id needs a cursor migration.
* **Report range (inclusive, at most 400 days).** The `to` date is inclusive and a range spans at most 400 days; the handler and the SQL function agree on the boundary (tests `TestPlatformReach*` and the PG boundary cases).
