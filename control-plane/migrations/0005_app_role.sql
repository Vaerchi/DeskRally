-- Control-plane least-privilege application role — the role RLS is ACTUALLY enforced against.
--
-- =====================================================================================
-- WHY THIS MIGRATION EXISTS (read the RLS strategy note at the top of 0001_core.sql first)
-- =====================================================================================
-- The whole multi-tenant isolation guarantee (ENABLE + FORCE ROW LEVEL SECURITY plus the
-- `tenant_isolation` policies of the form
--     USING (tenant_id = current_setting('app.current_tenant')::uuid)
-- on every tenant-scoped table) is ONLY effective when the application connects as a role
-- that is subject to RLS. PostgreSQL exempts two kinds of role from Row-Level Security:
--     * a SUPERUSER, and
--     * a role with the BYPASSRLS attribute,
-- and additionally exempts a table's OWNER unless FORCE ROW LEVEL SECURITY is set (it is,
-- here — defense in depth). A superuser is exempt EVEN WITH FORCE. So if the production
-- app connects as `postgres` / the schema owner (as every integration test does today —
-- see the note in pgstore_test.go), **RLS does nothing and tenants are NOT isolated**: a
-- forgotten `WHERE tenant_id = …` leaks every MSP's machines, sessions, and audit trail.
--
-- 0001_core.sql already mandates "The application connects as a NON-superuser, NON-owner
-- role" and 0004_audit.sql defers the "role grants … to a later migration". THIS is that
-- migration. It provisions `rmt_app`: a plain LOGIN role, no SUPERUSER, no BYPASSRLS, not
-- the owner of any table — so RLS genuinely applies to it (FORCE is not even required for a
-- non-owner). It is granted exactly the DML it needs and nothing more.
--
-- -------------------------------------------------------------------------------------
-- PRODUCTION REQUIREMENT (deployment hard rule):
--   The production DATABASE_URL MUST connect as `rmt_app` (this least-privilege, RLS-subject
--   role) — NOT as `postgres`, NOT as the migration/owner role. Apply migrations as the
--   admin/owner role, then point the app at rmt_app. Connecting the app as a superuser or
--   the owner SILENTLY BYPASSES RLS and breaks tenant isolation. See docs/10-deployment.md.
-- -------------------------------------------------------------------------------------
--
-- Idempotency: this file is re-runnable. Role creation is guarded by an IF NOT EXISTS DO
-- block (CREATE ROLE has no IF NOT EXISTS); GRANT / ALTER DEFAULT PRIVILEGES are naturally
-- idempotent. The integration tests DROP + recreate the tables between runs (resetSchema),
-- which drops the per-object grants with them, so re-applying this file re-establishes them.
-- =====================================================================================

-- 1) The role. Idempotent create, then pin its attributes explicitly so a pre-existing role
--    can never carry SUPERUSER/BYPASSRLS/CREATEDB/CREATEROLE that would defeat isolation.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        CREATE ROLE rmt_app LOGIN;
    END IF;
END
$$;

-- Enforce the safe attribute set every time (defensive; NOBYPASSRLS is the load-bearing one).
ALTER ROLE rmt_app WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;

-- Password: intentionally NOT set here. Local/dev uses `trust` auth (no password needed);
-- production provisions the password/DSN out-of-band so no throwaway secret is committed to
-- a migration that ships in dist/servers/migrations. To set one locally if your pg_hba
-- requires it: ALTER ROLE rmt_app PASSWORD 'rmt_app';

-- 2) Schema + object privileges — exactly what the app needs, no more.
GRANT USAGE ON SCHEMA public TO rmt_app;

-- DML on all current tables. (RLS still filters every row to the pinned tenant; these grants
-- only get the role in the door — the policies decide what it may see/write.)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO rmt_app;
-- Sequences: needed for any serial/identity defaults and nextval().
GRANT USAGE, SELECT               ON ALL SEQUENCES IN SCHEMA public TO rmt_app;
-- Functions: incl. the cp_* SECURITY DEFINER bootstrap helpers in 0003 (already GRANTed to
-- PUBLIC there; this is belt-and-suspenders). Those run as their OWNER (the migration/admin
-- role) and legitimately bypass RLS to resolve a tenant slug / session token BEFORE a tenant
-- can be pinned — rmt_app only needs EXECUTE, which it has.
GRANT EXECUTE ON ALL FUNCTIONS    IN SCHEMA public TO rmt_app;

-- 3) Future objects created by the migration/owner role are covered automatically, so a new
--    table in a later migration does not silently become unreadable by the app (or, worse,
--    prompt someone to re-grant as superuser). These attach to objects created by the role
--    running THIS migration — i.e. the schema owner, which is who should be creating tables.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES    TO rmt_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT               ON SEQUENCES TO rmt_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT EXECUTE                     ON FUNCTIONS  TO rmt_app;

-- 4) Preserve 0004_audit.sql's append-only contract for the backstage audit chain: the app
--    may INSERT + SELECT but must never UPDATE/DELETE a stored, hash-chained audit event
--    (retention/purge runs as a separate privileged job). Guarded so this file still applies
--    cleanly against a schema where 0004 has not (yet) been run — e.g. the RLS integration
--    test, which only lays down 0001–0003 before applying this migration.
DO $$
BEGIN
    IF to_regclass('public.backstage_audit_event') IS NOT NULL THEN
        REVOKE UPDATE, DELETE ON backstage_audit_event FROM rmt_app;
    END IF;
END
$$;
