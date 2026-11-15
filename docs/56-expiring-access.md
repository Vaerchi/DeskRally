# docs/56: Expiring access (timed memberships)

**Status:** design r3 (Codex r1 repair → r2 repair (2 medium) → r3; see §10), 2026-10-29. Closes the expiring half of the parity item
"P2 Timed / expiring access and scheduled access windows". Scheduled windows (weekday 9-to-5) are
out of scope here (§8).

## 1. What it is

An operator gives a user access **until a date and time**: a contractor for a week, a temporary
helper during an incident. When that moment passes, the access stops by itself, with no job to run and
nothing to forget:

- the console and API refuse everything that membership granted, from the next request on;
- an UNATTENDED remote session the user holds stops being RENEWED at once (every ~10 s renewal
  re-checks the grant) and the agent tears it down when its current lease runs out: about 32 s after
  the deadline at most (30 s lease TTL + the agent's 2 s enforcement tick), plus any clock skew between
  the server and the agent's machine (the agent judges lease expiry on its own clock, docs/25 F03);
- an ATTENDED session already running at the deadline (a guest present, who consented and can end it)
  continues until it ends; no new attended or unattended session can start;
- the Users panel shows "Expires 5 Nov 17:00" before, and "Expired" after, so an admin can extend it.

**Exceptions, stated in the editor too (§7):** API tokens are their own principals and do not expire
with the user who minted them; login sessions stay signed in (with no capability).

## 2. The one rule

A membership with `expires_at` in the past grants nothing. It is enforced in exactly one place:
`UserStore.GrantFor`, which already resolves a user's grant on **every** authenticated request
(auth.go:316). Nothing in SQL reads `membership` for authorization (inventory: the only `FROM membership`
reads are GrantFor, ListUsers and the admin write paths in pgstore.go), so the filter cannot be bypassed
by a path that never calls GrantFor.

Everything that gates on a principal's grant inherits expiry, including:

- every console/API capability check (`Require`, `AllowsInGroup`, scope filters);
- **live UNATTENDED sessions**: `POST /sessions/{id}/policy` (http_session_lease.go) re-resolves the
  capability on every ~10 s renewal; when it fails the lease is not renewed and the agent ends the
  session when the current lease (30 s TTL) runs out, the same mechanism that already ends a session
  when a machine leaves the caller's scope. Attended sessions have no lease (§1);
- elevation minting, transfer offers/acceptance (http_session_transfer.go calls GrantFor), audit
  export scoping.

**Time source (r2):** the DATABASE clock decides whether a membership grants: GrantFor's predicate
uses `statement_timestamp()` (not `now()`, which is the transaction start; GrantFor runs in a short
read-only transaction, so the two differ by milliseconds, but statement time is the honest one). The
app server's clock only VALIDATES new input (§4: "at least one minute ahead"); the API server and the
database run on the same host here, and the one-minute floor absorbs ordinary skew. The observable
end of access is therefore: AUTHORIZATION stops at `expires_at` on the DB clock (every request and
every lease renewal from then on is refused); TERMINATION of a live unattended session follows within
~32 s (lease TTL + enforcement tick) on the AGENT's clock, so a skewed agent clock shifts teardown by
its skew. That matches today's behaviour for every other lease-based end; no new hard deadline is
claimed.

## 3. Schema (migration 0062)

```sql
ALTER TABLE membership ADD COLUMN expires_at timestamptz;   -- NULL = never expires
```

No backfill (existing memberships keep NULL = today's behaviour). No index needed: GrantFor reads one
user's handful of rows by the existing `idx_membership_user`.

GrantFor's query gains `AND (m.expires_at IS NULL OR m.expires_at > statement_timestamp())`. The in-memory fake store
applies the same rule with its clock (fake/pg must agree; a shared contract test runs against both).

## 4. Setting it

### API

`POST /users/{id}/role` (setUserRoleRequest) and the invite (`POST /users`) gain an optional field:

```json
{ "role": "technician", "scoped_group_ids": [...], "expires_at": "2026-11-05T17:00:00Z" }
```

- **ABSENT → preserve** the target's STORED expiry (docs/55's rule for scope: a role change must not
  silently make temporary access permanent). A preserved expiry is carried as stored, EVEN IF it is
  already in the past (an unrelated edit must not fail validation, and must not silently re-enable
  access): renewing access is always an explicit new timestamp or null.
- **`null` → never expires** (an explicit clear).
- **A timestamp → that moment**, RFC 3339 with an offset. It must be at least one minute ahead (server
  time) and at most 5 years ahead (a typo guard). 400 otherwise. Only a SUPPLIED timestamp is validated.
- **Presence-aware decoding (r2):** the field is decoded as `json.RawMessage`, so absent (nil),
  `null` and a string are three distinct cases; any other JSON type is a 400.
- **Stored, not effective (r2):** the handler reads the target's STORED assignment through a new
  `UserStore.StoredAssignment(tenant, user)`, which returns ALL membership rows INCLUDING expired ones
  (role, scope, expires_at). Preservation of scope AND expiry, and escalation guard #1, use the stored
  assignment, never the expiry-filtered grant (§4 guards). `SetUserRole` collapses all rows into one
  (as today). **Heterogeneous rows (r3):** when the stored rows differ in scope OR expiry, preserving
  either one is ambiguous (collapsing an expired row's scope with a live row's deadline could revive
  expired access), so an edit that OMITS scope or `expires_at` for such a user is a 400 ("this user has
  several memberships; send scoped_group_ids and expires_at explicitly"). With homogeneous rows (the
  console only ever writes one) the single stored value is preserved. The resolved value actually
  written is what the audit records.

### Guards (in the handler, before any write)

1. **No expiry on the Owner role.** Checked against the RESULTING assignment: role Owner with a
   supplied OR PRESERVED non-null expiry is a 400 ("owner access cannot expire; clear the expiry"), so
   promoting a temporary user to Owner requires an explicit `"expires_at": null`.
2. **Guard #1 uses the STORED assignment (r2).** "The actor must be able to administer the target as
   they are" is evaluated against a grant built from ALL stored rows, expired included. An expired
   Admin is still protected from a Technician-manager; expiry never lowers who may edit a user. The
   same stored grant replaces GrantFor at EVERY target-protection site: role set, disable, password
   reset, session sign-out, TOTP-lockout clear, OIDC unlink (auth_user_admin.go x4,
   auth_password_reset.go, http_oidc.go). Guard #2 (the actor covers the NEW assignment) is unchanged.
   Expiry only reduces what a grant gives, so it adds no escalation path of its own.
2a. **A permanent Owner always remains (r2, closes a pre-existing race).** Today two Owners demoting or
   disabling each other concurrently could leave none. `SetUserRole` and the disable write, in their
   transaction, lock the tenant's Owner membership rows (`SELECT ... FOR UPDATE`) and refuse
   (`ErrLastOwner` → 409) a change that would leave no ENABLED Owner membership with NULL expiry.
3. **Not on yourself** (already refused for any role change; the same self-lockout reasoning).
4. Expiry is per membership. Today's console writes exactly one membership per user (SetUserRole
   replaces all), so in practice it is per user; the store keeps it per row so multi-membership users
   (API tokens aside) stay well-defined: the user's effective grant is the union of their UNEXPIRED
   memberships.

### Audit

`user.role_set` and `user.created` carry `expires_at` (RFC 3339 or null). The expiry moment itself is
not an event (nothing happens at that instant; access simply stops being granted). The next denied
request is the observable effect; ListUsers shows "Expired".

## 5. Reading it

`UserSummary` gains (from the stored rows):

- `access_expires_at` (RFC 3339 or null): null when ANY of the user's memberships never expires;
  otherwise the LATEST expiry among their memberships (when the last access ends);
- `access_expired` (bool): the user has memberships and all of them are expired.

Roles and scope in ListUsers keep listing every membership (expired included), so an admin sees what
expired and can extend it in place; the Expired badge says it grants nothing.

`GET /me` (HandleMe) adds `access_expired` AND `access_expires_at` (same aggregate), so the console can
say "Your access to this organization expired on 5 Nov 17:00; ask an administrator" instead of a wall
of 403s. /me needs no capability, so it answers an expired user (verify in tests).

## 6. Console (viewer)

- **Users panel, role editor and invite form:** an "Access expires" control: *Never* (default) or a
  date + time (local time, sent as UTC). Pre-filled with the current value when editing; the request
  OMITS `expires_at` unless the operator changed it (so an unchanged, already-past expiry is preserved,
  not rejected). The control carries one line: "API tokens are not affected".
- **Users table:** an Expires column ("Never", "5 Nov 17:00", or an "Expired" badge).
- **Signed-in expired user:** a single banner from `/me` and no panels.

## 7. What it deliberately does NOT do

- **API tokens are unaffected.** A token is its own principal with its own capabilities and its own
  expiry (apitoken.go), not tied to the user who minted it; today a role change or disable does not
  revoke tokens either. In practice the exposure is small: minting is Owner-only and Owner access
  cannot expire, so only a FORMER Owner later given expiring access can hold tokens. Stated in the
  editor; an admin revokes tokens in the API Tokens panel.
- **Login sessions are not revoked at expiry.** The user can still sign in; they just hold no
  capability. (A disable is the tool for "this person must not sign in at all".) Revoking sessions at
  expiry would need a job; the per-request grant already removes every capability.
- **No notification before expiry** (a later addition via the console bell / webhooks).
- **SSO-provisioned memberships** keep NULL unless an admin sets an expiry afterwards.

## 8. Out of scope: scheduled access windows

Recurring windows (weekdays 09:00-17:00 in a time zone) are a different shape (a schedule, a time zone,
DST) and need their own design. The single-instant expiry here is the common MSP need ("until the
contract ends") and composes with a later schedule column.

## 9. Tests

- Store contract (fake AND pg): an expired membership grants nothing; an unexpired one still grants;
  NULL never expires; a user with one expired and one live membership gets exactly the live one's
  capabilities and scope.
- Handler: absent preserves, null clears, past/too-far/garbage → 400, Owner + expiry → 400, self → 400,
  escalation guards unchanged; audit rows carry expires_at.
- Lease: a session whose holder's membership expires is NOT renewed (403), proving live sessions end.
- ListUsers/me: access_expires_at and access_expired for never / future / mixed / all-expired.
- Viewer: the editor round-trips Never and a date; the Expired badge renders; the me-banner shows.
- r3: an expired + a live membership with different scopes: an edit omitting scope or expiry → 400.
- r2: expired higher-role target cannot be edited by a lower admin; absent scope after expiry is
  preserved from the stored rows; promotion to Owner with a preserved expiry → 400, with explicit null
  → ok; concurrent mutual Owner demotion leaves one Owner (pg, two transactions); presence-aware
  decoding (absent / null / string / number); a past preserved expiry passes an unrelated edit; the
  exact boundary (expires_at = statement time) denies; /me answers an expired user with the date.
- Mutation: removing the GrantFor filter fails the store contract and the lease test; using the
  filtered grant for guard #1 fails the expired-target test; dropping the Owner lock fails the race test.

## 10. Codex r1 → r2

1. [high] absent scope preserved from the filtered grant → StoredAssignment (§4).
2. [high] guard #1 against a powerless-looking expired target → stored grant at every target site (§4.2).
3. [high] last Owner → transactional permanent-Owner invariant (§4.2a); Owner+expiry checked on the
   resulting assignment (§4.1).
4. [medium] absent vs null; multi-row collapse → RawMessage decoding; aggregate rule; audit the
   resolved value (§4).
5. [medium] clocks → DB statement time decides; server time only validates; lease bound stated (§2).
6. [medium] API tokens → stated exception, editor text, Owner-only minting bounds it (§1, §7).
7. [medium] /me without a date; prefilled past expiry → /me returns the date; unchanged → omitted;
   preserved past values pass (§4, §5, §6).

Round 2 (2 medium):
8. mixed-expiry collapse could revive an expired row's scope → heterogeneous rows require explicit
   scope and expiry (§4); test: an expired + a live row, edit omitting either → 400.
9. the termination bound → authorization cutoff (DB clock) vs teardown (~32 s, agent clock, skew) (§1, §2).

Coverage notes: attended sessions continue to their end (stated, §1); elevation grants are short-lived
signed credentials minted per request through GrantFor-gated handlers; transfer acceptance calls
GrantFor; backstage runs inside an unattended session (lease-bound).
