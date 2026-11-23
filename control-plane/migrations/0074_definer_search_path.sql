-- 0074 — every SECURITY DEFINER routine has exactly `search_path = pg_catalog, public, pg_temp` (Codex H1).
--
-- A definer function runs as its owner, which in production is the migration role: rolsuper and
-- bypassrls. PostgreSQL searches the session's temporary schema FIRST for relations unless the
-- search_path names pg_temp explicitly, so `SET search_path = public, pg_catalog` does not stop a
-- caller from shadowing `tenant` (or any table a function reads) with a TEMP VIEW. rmt_app has TEMP
-- on the database, and a temp view can call a function that then runs as the definer: the
-- application role could execute code as a superuser. Measured on production 2026-11-03 (ledger at
-- 0070): 28 definer functions, 17 without a trailing pg_temp, 15 of those executable by rmt_app. 0071
-- has since redefined cp_attended_redeem safely; a fresh migrate to 0073 has 16, all fixed here.
--
-- The set is DERIVED from the catalog, not hand-listed: a hand list had already missed a live
-- function (cp_attended_redeem). The test is EXACT EQUALITY with the canonical setting, not "ends in
-- pg_temp": `pg_temp, public, pg_temp` and `public, "evil,pg_temp"` both end in pg_temp and are both
-- unsafe, and no pattern over the text is a search_path parser. Every application definer routine
-- (schema public, not an extension member) gets the canonical path — the one the newer definer
-- functions already use — via ALTER ROUTINE, which changes only that one setting: bodies, other SET
-- clauses, ownership and ACLs are untouched, so no function is redefined (and none from a stale copy).
-- pg_catalog moving ahead of public changes no resolution: the full-migrate test asserts no public
-- relation, type or function shares a name with a pg_catalog one, except pgcrypto's gen_random_uuid(),
-- which the PostgreSQL 13+ built-in matches exactly.
--
-- A definer routine in ANY OTHER schema, or one that belongs to an extension, with a different path is
-- REFUSED, and the migration rolls back: replacing its path with `public` could break it or resolve a
-- different object, so it needs a deliberate decision. There are none today.
--
-- A definer routine added by a later migration must SET the same path; the full-migrate test fails
-- otherwise.
DO $$
DECLARE
    fn record;
BEGIN
    FOR fn IN
        SELECT n.nspname, p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid) AS args,
               (SELECT c FROM pg_catalog.unnest(p.proconfig) AS c WHERE c LIKE 'search\_path=%') AS cfg,
               n.nspname = 'public' AND NOT EXISTS (
                   SELECT 1 FROM pg_catalog.pg_depend d
                   WHERE d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass AND d.objid = p.oid AND d.deptype = 'e'
               ) AS ours
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE p.prosecdef
          AND n.nspname NOT LIKE 'pg\_%'           -- pg_catalog, pg_toast, pg_temp_N: user schemas cannot start with pg_
          AND n.nspname <> 'information_schema'
        ORDER BY 1, 2, 3
    LOOP
        CONTINUE WHEN fn.cfg IS NOT DISTINCT FROM 'search_path=pg_catalog, public, pg_temp';
        IF NOT fn.ours THEN
            RAISE EXCEPTION '0074: SECURITY DEFINER routine %.%(%) (search_path %) is outside the application''s '
                'routines (another schema, or an extension member); its path needs a deliberate fix, not this one',
                fn.nspname, fn.proname, fn.args, COALESCE(fn.cfg, 'unset');
        END IF;
        -- ROUTINE, not FUNCTION: a SECURITY DEFINER procedure needs the same, and ALTER FUNCTION refuses one.
        EXECUTE pg_catalog.format('ALTER ROUTINE %I.%I(%s) SET search_path = pg_catalog, public, pg_temp',
                                  fn.nspname, fn.proname, fn.args);
        RAISE NOTICE '0074: %.%(%) % -> search_path=pg_catalog, public, pg_temp',
            fn.nspname, fn.proname, fn.args, COALESCE(fn.cfg, 'search_path unset');
    END LOOP;
END
$$;
