# docs/57: Scheduled access windows

**Status:** built 2026-10-29 (design r3; Codex r1 repair: 1 high, 5 medium; r2 repair: 2 medium; see §9). Migration 0063. Closes the second half of the parity item "P2 Timed / expiring
access and scheduled access windows" (docs/56 §8 left it out). Builds directly on docs/56: same
enforcement point, same preserve/clear/set API rules, same Owner and last-Owner guards.

## 1. What it is

An operator limits a user's access to **set hours on set days in a time zone**: "Mon-Fri 08:00-18:00
Europe/London" for a contractor, "Sat-Sun 00:00-24:00" for a weekend on-call helper, "Mon-Fri
22:00-06:00" for a night shift. Outside the window the user holds no capability, exactly like an
expired user (docs/56 §1):

- the console and API refuse everything that membership granted, from the next request on;
- an UNATTENDED session the user holds stops being renewed when the window closes and ends about 32 s
  later (lease TTL + agent tick, docs/56 §1, agent-clock caveat included);
- an ATTENDED session already running when the window closes continues until it ends (a guest is
  present and can end it); no new session can start;
- when the window opens again, access returns by itself on the next request (if the membership has
  not expired by then). Nothing is stored or scheduled; the rule is evaluated every time.

A window and an expiry compose: a membership grants only while it is unexpired AND inside its window
(when it has one).

## 2. The rule and where it is enforced

A membership grants at instant `t` iff `(expires_at IS NULL OR expires_at > t) AND window_open(t)`.
It is enforced in the same single place as expiry: `UserStore.GrantFor` (pg: in SQL, at
`statement_timestamp()`; fake: in Go at `time.Now()`). docs/56 §2's inventory still holds (no other
SQL reads `membership` for authorization), so everything that gates on a grant inherits windows:
capability checks, unattended lease renewal (http_session_lease.go), transfer, elevation minting,
audit export scoping.

### Window semantics

A window is `{days, start, end, time_zone}`:

- `time_zone`: an IANA name (`Europe/London`, `America/New_York`, `UTC`). The local wall clock in that
  zone decides; DST is followed automatically.
- `start`, `end`: wall-clock minutes, `start` in 00:00..23:59, `end` in 00:01..24:00, `start != end`.
- `days`: a non-empty subset of Mon..Sun. **A day names the day the window STARTS.**
- `start < end`: open on each listed day from `start` (inclusive) to `end` (exclusive).
- `end <= start` (crosses midnight): open from `start` on a listed day until `end` on the FOLLOWING
  day. "Fri 22:00-06:00" is Friday 22:00 to Saturday 06:00.

At instant `t`, let `L` be `t` in `time_zone`, `d` its weekday, `m` its minute of day
(`hour*60+minute`, seconds truncated, so 16:59:59 is minute 1019). The window is open iff

```
start < end:   d in days AND start <= m < end
end <= start:  (d in days AND m >= start) OR (d-1 in days AND m < end)
```

**DST:** evaluation is on the local wall clock, so the rule needs no special case. In a spring-forward
gap the skipped minutes never occur: a window starting inside the gap opens at the first later local
minute that exists, if that is still before its end; a window lying wholly inside the gap does not open
that day (Europe/London 2026-03-29 skips 01:00-01:59). In a fall-back repeat (London 2026-10-25 repeats
01:00-01:59) a window ending at 01:30 closes at the first 01:30 and is open again from the repeated
01:00 to 01:30. The editor help says "follows local time, including daylight-saving changes".

## 3. Schema (migration 0063)

```sql
ALTER TABLE membership
    ADD COLUMN window_days  smallint,  -- bitmask, bit d = weekday d, 0 = Sunday (pg extract(dow))
    ADD COLUMN window_start smallint,  -- minutes after local midnight, 0..1439
    ADD COLUMN window_end   smallint,  -- 1..1440
    ADD COLUMN window_tz    text,
    ADD CONSTRAINT membership_window_complete CHECK (
        (window_days IS NULL AND window_start IS NULL AND window_end IS NULL AND window_tz IS NULL)
     OR (window_days IS NOT NULL AND window_start IS NOT NULL AND window_end IS NOT NULL AND window_tz IS NOT NULL)),
    ADD CONSTRAINT membership_window_range CHECK (
        window_days IS NULL OR (window_days BETWEEN 1 AND 127
            AND window_start BETWEEN 0 AND 1439 AND window_end BETWEEN 1 AND 1440
            AND window_start <> window_end));

CREATE FUNCTION membership_window_open(days smallint, s smallint, e smallint, tz text, at timestamptz)
RETURNS boolean LANGUAGE plpgsql STABLE ...  -- NOT STRICT: NULL days -> true; otherwise §2's predicate
```

The function is plpgsql so it can FAIL CLOSED without failing the query: the NULL-days case returns true
before any zone work; otherwise the conversion runs inside `BEGIN ... EXCEPTION WHEN OTHERS THEN RETURN
false` (r2). A zone pg cannot evaluate therefore denies that one membership instead of raising, so
GrantFor still answers (with the user's other memberships) and ListUsers still lists everyone, keeping
the row repairable from the console.

All-NULL = no window (today's behaviour; no backfill). The schema owns completeness and ranges. The
time zone's VALIDITY cannot be a CHECK (it depends on the tz database), so the pg write path checks it
in the same transaction against `pg_timezone_names` (§4) — the database that will evaluate it is the
authority. A name valid at write time and later removed from tzdata (IANA turns retired names into
links, so this is theoretical) makes that membership grant nothing (the function's fail-closed branch).

**PostgreSQL is the production authority (r2).** In production every decision that depends on the
clock or the tz database is made in SQL at one `statement_timestamp()`: GrantFor, ListUsers' summary
AND /me's summary (§5). Go never evaluates a window in production; it only pre-validates input, and the
pg write path then checks the exact name against `pg_timezone_names`. The Go evaluator (`OpenAt`) serves
the in-memory fake store (dev/tests). Go's tzdata (the embedded `time/tzdata`, used only when the
system has no zoneinfo) and pg's can be different releases, so the fake/pg vector test proves the two
PREDICATES agree on stable rules; it does not, and need not, prove two tz databases agree, because they
never both decide in one deployment. pg's tzdata follows the postgres image (system tzdata on Debian);
updating the image updates the rules. The fake's invalid zone denies (OpenAt returns false); it never
falls back to UTC or Local.

GrantFor: `AND membership_window_open(m.window_days, m.window_start, m.window_end, m.window_tz,
statement_timestamp())`. ListUsers, StoredGrantFor and the last-Owner count read the new columns.

## 4. Setting it

### API

`POST /users/{id}/role` and `POST /users` gain an optional `access_window`, with docs/56's three-way
presence rule:

```json
{ "role": "technician", "expires_at": null,
  "access_window": { "days": ["mon","tue","wed","thu","fri"], "start": "08:00", "end": "18:00",
                     "time_zone": "Europe/London" } }
```

- ABSENT → preserve the STORED window (from StoredGrantFor), the same as scope and expiry. **A
  preserved window is carried EXACTLY as stored (r3):** no Go zone load and no pg name re-check, so an
  unrelated edit never fails on a zone that has since become unsupported; that window keeps denying
  (fail closed) until an operator clears or replaces it. Only a SUPPLIED window is validated.
- **One heterogeneity rule (r2):** if the stored rows differ in scope, expiry OR window, the edit must
  supply ALL THREE of `scoped_group_ids`, `expires_at` and `access_window` explicitly; omitting any one
  is a 400 ("this user has several memberships; send scoped_group_ids, expires_at and access_window
  explicitly"). Otherwise a preserved aggregate could merge "group A by day" and "group B by night"
  into "A and B at any time". `Grant.Homogeneous` compares all three; the handler's existing condition
  is extended in the same change, and tests omit each field in turn against window-only heterogeneity.
- `null` → no window (any time).
- an object → that window. Validation (400 on failure): `days` a non-empty list of distinct
  `sun mon tue wed thu fri sat`; `start` `HH:MM` 00:00..23:59; `end` `HH:MM` 00:01..24:00 (24:00 only
  as end); `start != end`; `time_zone` a supported name: Go `time.LoadLocation` succeeds (the binary
  embeds `time/tzdata`: the alpine runtime image has no zoneinfo), the name is not `Local`, and it
  matches `^[A-Za-z][A-Za-z0-9_+\-]*(/[A-Za-z0-9_+\-]+)*$` (rejects POSIX rule strings like
  `EST5EDT,M3.2.0,M11.1.0` and bare offsets like `+05`, which pg would read with an inverted sign). The
  pg write path then requires an EXACT match in `pg_timezone_names` (`ErrUnknownTimeZone` → 400).
  **Policy (r2):** any name in the tz database is accepted, including legacy and `Etc/` names
  (`EST5EDT`, `Etc/GMT+5`): they are real tz database entries with well-defined rules. The console only
  offers the browser's canonical list (§6).

### Guards

1. **No window on the Owner role** (resulting assignment, supplied OR preserved), as for expiry: an
   Owner must always be able to administer the tenant. Promoting a windowed user to Owner needs an
   explicit `"access_window": null`.
2. **Last permanent Owner** (docs/56 §4.2a): the count requires `expires_at IS NULL AND window_days IS
   NULL`. Unchanged otherwise (guard 1 already keeps windows off Owners; this keeps the invariant
   honest if a row is written another way).
3. Target protection uses StoredGrantFor (docs/56), which now ignores windows as well as expiry: a
   user outside their window keeps their protection.
4. Not on yourself (existing).

### Audit

`user.role_set` and `user.created` carry `access_window` (the object, or null) as resolved.

## 5. Reading it

`UserSummary` gains:

- `access_window`: non-null ONLY when every membership carries the same non-null window (that window);
  `null` otherwise (no memberships, any membership unrestricted, or windows that differ);
- `access_window_varies` (bool, r3): the memberships do NOT all carry the same window, counting "no
  window" as a value: different windows, OR a mix of windowed and unrestricted rows. So `access_window`
  null with `varies` false means genuinely "any time"; the console never shows a mixed user as
  unrestricted (only the API can create one; the console writes one membership);
- `access_outside_window` (bool): a CURRENT predicate: the user has at least one unexpired membership
  and every unexpired membership is outside its window right now. It promises nothing about later (the
  memberships may expire before they next open).

**One evaluation, in the store (r2).** The access summary (docs/56's `access_expires_at` /
`access_expired` plus the three above) comes from a new `UserStore.AccessSummary(tenant, user)`, which
pg answers with the SAME SQL as ListUsers (one query, one `statement_timestamp()`, the windows evaluated
by `membership_window_open`), filtered to the one user; the fake answers from its stored grant at
`time.Now()`. /me uses it instead of recomputing expiry in Go (which today reads the app clock: a
docs/56 inconsistency this also removes).

`GET /me` adds `access_window`, `access_window_varies` and `access_outside_window`. The console banner:
expired → docs/56's message; outside the window with `access_window` set → "Your access is limited to
Mon-Fri 08:00-18:00 (Europe/London); it is outside those hours now"; outside with `access_window` null
(varying, or e.g. an expired unrestricted row plus a live closed window; r3) → the generic "Your access
is limited to set hours, and it is outside them now".

## 6. Console (viewer)

- **Access editor** (docs/56's, per user): a second section "Only at certain times": a checkbox,
  seven day toggles (Mon first), From / Until time inputs, an **"end of day"** checkbox next to Until
  (sends `24:00`, which a native time input cannot hold; a stored `24:00` round-trips to it checked), and
  a time-zone select. The select's options are `Intl.supportedValuesOf('timeZone')` when available
  PLUS `UTC` PLUS the stored zone (so an existing window always displays as stored, alias or not);
  default for a new window is the browser's zone. If the server rejects the zone, its message is shown
  and nothing changes. Help lines: "Days are the day the window starts; Until earlier than From runs
  past midnight" and "Follows local time, including daylight-saving changes". Unchanged → omitted (the
  dirty rule from docs/56). Disabled for an Owner.
- **Users table and editor for a mixed user (r3):** when `access_window_varies`, the Access column
  says "Hours vary by membership" and the editor opens with the window section showing "Varies; saving
  replaces it" and nothing pre-filled, so it never presents a mixed user as unrestricted. Saving a mixed
  user needs the explicit three fields (§4), which the editor sends (scope as listed, the expiry shown,
  the window chosen).
- **Users table:** the Access column adds the window ("Mon-Fri 08:00-18:00 London") under the expiry,
  and an "Outside hours" badge when `access_outside_window`.
- **Invite form (r2):** the same window fields (collapsed behind "Only at certain times"), sent with
  the invite in the one `POST /users`, so a restricted user is never created unrestricted first.
- **Signed-in user outside their window:** the banner from §5.

## 7. What it deliberately does NOT do

docs/56 §7 applies unchanged (API tokens unaffected; login sessions not revoked; no notifications;
SSO memberships start unrestricted). Plus:

- **One window per membership.** "Mon-Fri 09-17 and Sat 10-14" needs two memberships (API only). The
  common case is one span on a set of days.
- **No holidays or date exceptions.** Combine with an expiry or disable for those.
- **Attended sessions are not cut at the window's close** (same reason as expiry: a consenting guest
  is present). Unattended sessions are.

## 8. Tests

(r2 additions: heterogeneity omits each of the three fields in turn against window-only
heterogeneity; London DST vectors use the real gap/repeat 01:00-01:59; a pg row with a zone pg cannot
evaluate (written by SQL, bypassing the write check) denies that membership while GrantFor, ListUsers
and AccessSummary still answer; /me's summary comes from the store. r3: an expired unrestricted row
plus a live closed window reports window null, varies true, outside true in ListUsers and /me; an
unrelated role edit preserves a stored zone pg no longer knows, and access stays denied.)


- Go unit: window parse/format; `OpenAt` truth table incl. crossing midnight on a listed/unlisted day,
  24:00 end, minute truncation at 16:59:59/17:00:00, a DST spring-forward and fall-back day (Europe/
  London 2026-03-29 and 2026-10-25), and a zone east and west of UTC where the UTC weekday differs from
  the local one.
- **Fake/pg agree:** one table of (window, instant, expected) evaluated by Go `OpenAt` AND by
  `SELECT membership_window_open(...)` in pg — the same vectors, so the two implementations cannot
  drift.
- Contract (fake + pg): GrantFor drops an out-of-window membership and keeps an in-window one;
  StoredGrantFor returns both; ListUsers `access_window` / `_varies` / `_outside_window`; schema CHECKs
  reject partial and out-of-range rows; unknown zone rejected on write.
- Handler: three-way presence, validation 400s, Owner+window 400 (supplied and preserved),
  heterogeneous-window 400, audit payload, /me fields for an outside-window user (/me still answers).
- Lease: an unattended session's renewal is refused once the window closes (fake clock via the
  membership's window chosen to be closed now).
- Viewer: unit (format / parse helpers); e2e (set a window, preserve across role change, unchanged
  Save sends nothing, clear it, Owner disables the section).

## 9. Codex r1 → r2

r1 (repair): **[high]** heterogeneity must require all three of scope / expiry / window whenever any
differs (§4); **[medium]** tzdata parity: pg is the production authority for every clock decision, the
fake/pg test proves the predicates only (§3); **[medium]** /me recomputed in Go on the app clock: now a
store-level AccessSummary evaluated by pg (§5); **[medium]** aggregate semantics for differing windows
and a non-promising outside-window flag, varies exposed in /me (§5); **[medium]** 24:00 and zone-list
gaps in the UI: end-of-day control, UTC and the stored zone always offered (§6); **[medium]** invite then
edit left a window of unrestricted access: the invite carries the window (§6). Answers adopted: DST
qualification (§2), fail-closed function that cannot break ListUsers (§3), legacy-name policy (§4).

r2 (repair, 2 medium): **[medium]** the banner and editor for a user mixing windowed and unrestricted
rows: `access_window_varies` now counts "no window" as a value, the banner falls back to a generic
outside-hours line whenever `access_window` is null, and the editor shows "Varies" (§5, §6);
**[medium]** a preserved window is carried exactly as stored with no zone re-validation, only a supplied
one is checked (§4).
