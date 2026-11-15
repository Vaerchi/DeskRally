-- 0038 — seed the `elevate_session` capability onto the Owner and Admin preset roles.
--
-- WHAT THIS IS FOR, precisely, because it is easy to over- or under-read.
--
-- `role.capabilities` is NOT read at runtime: PgUserStore.GrantFor selects only `r.key` and expands
-- the preset through rbac.go's rolePresets map, so authorization comes from the CODE. This migration
-- therefore changes no behaviour. What it changes is the truth of a documented invariant: 0001_core's
-- preset seed calls itself "the authoritative source mirrored by rbac.go's rolePresets", and leaving
-- the column behind would make that statement false for the first reader who trusts it — including
-- a future change that decides to read the column.
--
-- WHO GETS IT. Owner (holds every capability by definition) and Admin. Deliberately NOT Technician:
-- a technician runs commands on a session, but taking the GUEST's own administrator identity —
-- their profile, their network credentials, their DPAPI secrets, at full admin — is an
-- administrator's decision. See the CapElevateSession doc in rbac.go, and docs/01 §3.
--
-- Forward-only and idempotent-safe: the NOT (… = ANY(…)) guard means re-running it (or applying it
-- to a database whose 0001 seed already carried the capability) is a no-op rather than a duplicate.
-- Preset rows are the ones with tenant_id IS NULL; per-tenant custom roles are never touched.

UPDATE role
   SET capabilities = capabilities || ARRAY['elevate_session']
 WHERE tenant_id IS NULL
   AND key IN ('owner', 'admin')
   AND NOT ('elevate_session' = ANY(capabilities));
