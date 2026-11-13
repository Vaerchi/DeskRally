-- 0076 — every application SECURITY DEFINER routine is owned by `rmt_definer`, not by the migration
-- role (docs/67; follow-up to Codex H1, whose immediate hazard 0074 closed).
--
-- A definer routine runs as its OWNER. Until now that was the migration role, which in production
-- is rolsuper and bypassrls, so a defect in ANY definer routine (dynamic SQL built from an argument,
-- an unqualified name in a later routine, a PostgreSQL bug) handed the caller a superuser: COPY ...
-- TO PROGRAM, file access, new roles. `rmt_definer` is the weakest role that still does the job:
--   * NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION, and no role memberships;
--   * BYPASSRLS, because bypassing RLS for the pre-tenant lookups (session token, attended code,
--     enrollment token, tenant slug, API token, platform operator) is why these routines exist;
--   * table privileges granted per table below, derived from what the routine bodies touch and then
--     confirmed by running the whole pg suite with the routines owned by it; it owns NO table, so it
--     cannot ALTER, DROP, TRUNCATE or switch off RLS on anything;
--   * no CREATE on any schema, no sequence or function privileges beyond PUBLIC's defaults.
-- A defect in a definer routine now yields "read/write THESE tables across tenants", not a superuser.
--
-- WHAT THE GRANTS ARE (one line per table, so a reader can diff them against the bodies):
--   SELECT     every table a routine reads (an UPDATE or DELETE also reads, through its WHERE);
--   INSERT     tenant (cp_create_tenant, cp_platform_create_tenant), machine (cp_attended_redeem_scoped),
--              tenant_hostname_assignment, tenant_branding_pointer, session_ticket_redemption;
--   UPDATE     tenant (suspension), attended_session, user_credential_token, enrollment_token, user_session,
--              session_record, tenant_hostname_assignment, tenant_branding_pointer;
--   DELETE     session_ticket_redemption only (the redemption-row sweep inside cp_session_ticket_redeem).
-- The definer-to-definer calls (cp_platform_check, cp_hostname_lock_tenant, ...) need no grant: the
-- callee has the same owner. Advisory locks need none either. No definer routine touches a sequence.
-- A NEW definer routine that needs more must add its GRANT in a later migration AND change the
-- expected set in TestPgDefinerOwnerRole: a new privilege is a deliberate decision, never a side effect.
--
-- OWNERSHIP is DERIVED from pg_proc, like 0074 (a hand list had already missed a live function once):
-- every definer routine in schema public that is not an extension member moves with ALTER ROUTINE ...
-- OWNER TO. ALTER OWNER rewrites the old owner's own ACL entries and nothing else, so the EXECUTE
-- grants to rmt_app and PUBLIC are identical afterwards (the full-migrate test compares them). A
-- definer routine anywhere else (another schema, or an extension member) is REFUSED and the migration
-- rolls back: moving it needs a deliberate decision.
--
-- THE MIGRATION ROLE MUST BE A SUPERUSER (it is, in production and in the test database): only a
-- superuser can grant BYPASSRLS, and only one can hand a function to a role that has no CREATE on the
-- schema (rmt_definer must NOT have it: schema public stays unwritable for every role but the owner).
-- Otherwise the migration stops with a clear message before changing anything.
--
-- A PRE-EXISTING rmt_definer is refused unless clean (no memberships, owns only routines, no privilege beyond the
-- table grants below, no CREATE anywhere): see the checks after the ALTER ROLE. In production the role is new.
--
-- A definer routine added by a LATER migration is created by the migration role and so is owned by it
-- again. It must end with `ALTER ROUTINE ... OWNER TO rmt_definer`; the full-migrate test fails otherwise.
--
-- ROLLBACK: ALTER ROUTINE ... OWNER TO <migration role> for each routine, then
-- REVOKE ALL ON ... FROM rmt_definer, DROP ROLE rmt_definer (docs/67 deploy note).

DO $$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION '0076: the migration role % is not a superuser; creating rmt_definer with BYPASSRLS and '
            'handing it the definer routines needs one. Nothing was changed. Run this migration as the '
            'superuser migration role (docs/67).', current_user;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rmt_definer') THEN
        BEGIN
            CREATE ROLE rmt_definer NOLOGIN;
        EXCEPTION WHEN duplicate_object THEN NULL;   -- a concurrent migration created it first
        END;
    END IF;
END
$$;

-- Pin the attributes EVERY run, so a pre-existing role can never carry LOGIN, SUPERUSER, CREATEDB,
-- CREATEROLE or REPLICATION. BYPASSRLS is the one deliberate attribute.
ALTER ROLE rmt_definer WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;

-- A pre-existing rmt_definer (an operator made it, or a restore brought it) is ADOPTED only if it is clean; this
-- migration REFUSES rather than cleans (the whole file rolls back, nothing is changed). In normal operation the
-- role is created above and every check below finds nothing. Refused:
--   * any role membership, either direction (a member could SET ROLE to it; being a member inherits rights);
--   * any object it owns other than routines (shared dependencies: tables, schemas, databases, types, ...);
--   * ANY explicit privilege outside the table grants below: on a schema other than USAGE on public, on any
--     database (the ACL is cluster-wide), tablespace, routine it does not own, sequence, view or any relation
--     outside schema public, any column, type, language, large object, foreign data wrapper or server, any
--     parameter (PostgreSQL 15+), and any default-privilege entry naming it. Revoking CREATE from PUBLIC does
--     not revoke a direct GRANT CREATE ON SCHEMA ... TO rmt_definer, so a direct grant must be found, not assumed away.
-- Table grants in schema public are compared with the GRANT lines after they ran (see the end of the file).
DO $$
DECLARE
    r pg_catalog.oid := 'rmt_definer'::pg_catalog.regrole::pg_catalog.oid;
    bad text;
BEGIN
    SELECT pg_catalog.string_agg(m.rolname || ' is a member of rmt_definer', '; ') INTO bad
    FROM pg_catalog.pg_auth_members a JOIN pg_catalog.pg_roles m ON m.oid = a.member
    WHERE a.roleid = r;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION '0076: rmt_definer already exists and other roles belong to it (%); revoke them first (docs/22, docs/67)', bad;
    END IF;
    SELECT pg_catalog.string_agg('rmt_definer is a member of ' || p.rolname, '; ') INTO bad
    FROM pg_catalog.pg_auth_members a JOIN pg_catalog.pg_roles p ON p.oid = a.roleid
    WHERE a.member = r;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION '0076: rmt_definer already exists and belongs to other roles (%); revoke them first (docs/22, docs/67)', bad;
    END IF;
    SELECT pg_catalog.string_agg(pg_catalog.pg_describe_object(d.classid, d.objid, d.objsubid), '; ') INTO bad
    FROM pg_catalog.pg_shdepend d
    WHERE d.refclassid = 'pg_catalog.pg_authid'::pg_catalog.regclass
      AND d.refobjid = r
      AND d.deptype = 'o'
      AND d.classid <> 'pg_catalog.pg_proc'::pg_catalog.regclass      -- routines are what it is FOR
      AND d.dbid IN (0, (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database()));
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION '0076: rmt_definer already exists and owns objects other than routines (%); it must own none (docs/22, docs/67)', bad;
    END IF;

    SELECT pg_catalog.string_agg(q.f, '; ' ORDER BY q.f) INTO bad FROM (
        SELECT 'schema ' || n.nspname || ' ' || a.privilege_type AS f
          FROM pg_catalog.pg_namespace n, pg_catalog.aclexplode(n.nspacl) a
         WHERE a.grantee = r AND NOT (n.nspname = 'public' AND a.privilege_type = 'USAGE' AND NOT a.is_grantable)
        UNION ALL
        SELECT 'database ' || d.datname || ' ' || a.privilege_type
          FROM pg_catalog.pg_database d, pg_catalog.aclexplode(d.datacl) a WHERE a.grantee = r
        UNION ALL
        SELECT 'tablespace ' || t.spcname || ' ' || a.privilege_type
          FROM pg_catalog.pg_tablespace t, pg_catalog.aclexplode(t.spcacl) a WHERE a.grantee = r
        UNION ALL
        SELECT 'routine ' || p.oid::pg_catalog.regprocedure::text || ' ' || a.privilege_type
          FROM pg_catalog.pg_proc p, pg_catalog.aclexplode(p.proacl) a WHERE a.grantee = r AND p.proowner <> r
        UNION ALL
        -- a table in public is judged against the GRANT lines below; anything else of the kind is refused
        SELECT 'relation ' || n.nspname || '.' || c.relname || ' ' || a.privilege_type
          FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace,
               pg_catalog.aclexplode(c.relacl) a
         WHERE a.grantee = r AND NOT (n.nspname = 'public' AND c.relkind IN ('r', 'p'))
        UNION ALL
        SELECT 'column ' || c.relname || '.' || t.attname || ' ' || a.privilege_type
          FROM pg_catalog.pg_attribute t JOIN pg_catalog.pg_class c ON c.oid = t.attrelid,
               pg_catalog.aclexplode(t.attacl) a WHERE a.grantee = r
        UNION ALL
        SELECT 'type ' || t.oid::pg_catalog.regtype::text || ' ' || a.privilege_type
          FROM pg_catalog.pg_type t, pg_catalog.aclexplode(t.typacl) a WHERE a.grantee = r
        UNION ALL
        SELECT 'language ' || l.lanname || ' ' || a.privilege_type
          FROM pg_catalog.pg_language l, pg_catalog.aclexplode(l.lanacl) a WHERE a.grantee = r
        UNION ALL
        SELECT 'large object ' || l.oid || ' ' || a.privilege_type
          FROM pg_catalog.pg_largeobject_metadata l, pg_catalog.aclexplode(l.lomacl) a WHERE a.grantee = r
        UNION ALL
        SELECT 'foreign data wrapper ' || w.fdwname || ' ' || a.privilege_type
          FROM pg_catalog.pg_foreign_data_wrapper w, pg_catalog.aclexplode(w.fdwacl) a WHERE a.grantee = r
        UNION ALL
        SELECT 'foreign server ' || s.srvname || ' ' || a.privilege_type
          FROM pg_catalog.pg_foreign_server s, pg_catalog.aclexplode(s.srvacl) a WHERE a.grantee = r
        UNION ALL
        SELECT 'default privileges ' || d.oid
          FROM pg_catalog.pg_default_acl d
         WHERE d.defaclrole = r OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(d.defaclacl) a WHERE a.grantee = r)
    ) q;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION '0076: rmt_definer already exists and holds privileges beyond its table grants (%); revoke them first, this migration does not clean them (docs/22, docs/67)', bad;
    END IF;
    IF pg_catalog.to_regclass('pg_catalog.pg_parameter_acl') IS NOT NULL THEN   -- PostgreSQL 15+
        EXECUTE 'SELECT pg_catalog.string_agg(''parameter '' || p.parname || '' '' || a.privilege_type, ''; '')
                 FROM pg_catalog.pg_parameter_acl p, pg_catalog.aclexplode(p.paracl) a WHERE a.grantee = $1'
            INTO bad USING r;
        IF bad IS NOT NULL THEN
            RAISE EXCEPTION '0076: rmt_definer already exists and holds parameter privileges (%); revoke them first (docs/22, docs/67)', bad;
        END IF;
    END IF;

    -- What it holds on tables in public now, to be compared with what the GRANT lines leave it (end of file).
    PERFORM pg_catalog.set_config('rmt_definer.pre_table_grants', COALESCE((
        SELECT pg_catalog.string_agg(c.relname || ' ' || a.privilege_type || ' ' || a.is_grantable::text, E'\n')
        FROM pg_catalog.pg_class c, pg_catalog.aclexplode(c.relacl) a
        WHERE a.grantee = r AND c.relnamespace = 'public'::pg_catalog.regnamespace AND c.relkind IN ('r', 'p')), ''), true);
END
$$;

-- Schema public must stay unwritable for it. PostgreSQL 14 (docs/10 supports it) lets PUBLIC create in public;
-- PostgreSQL 15+ already does not, so this is a no-op there.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO rmt_definer;

-- Start the tables from nothing, so the lines below are the whole surface (the check at the end of the file has
-- already recorded what was there and refuses if it was more).
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM rmt_definer;

-- One statement per line: the test fixture applies exactly these lines to the tables that exist so far.
GRANT SELECT                         ON TABLE agent_directive             TO rmt_definer;
GRANT SELECT                         ON TABLE api_token                   TO rmt_definer;
GRANT SELECT                         ON TABLE app_user                    TO rmt_definer;
GRANT SELECT, UPDATE                 ON TABLE attended_session            TO rmt_definer;
GRANT SELECT, UPDATE                 ON TABLE enrollment_token            TO rmt_definer;
GRANT SELECT                         ON TABLE help_request                TO rmt_definer;
GRANT SELECT                         ON TABLE help_request_call           TO rmt_definer;
GRANT SELECT                         ON TABLE help_request_op             TO rmt_definer;
GRANT SELECT, INSERT                 ON TABLE machine                     TO rmt_definer;
GRANT SELECT                         ON TABLE platform_config             TO rmt_definer;
GRANT SELECT                         ON TABLE platform_operator           TO rmt_definer;
GRANT SELECT                         ON TABLE session_recording           TO rmt_definer;
GRANT SELECT                         ON TABLE session_recording_segment   TO rmt_definer;
GRANT SELECT, UPDATE                 ON TABLE session_record              TO rmt_definer;
GRANT SELECT, INSERT, DELETE         ON TABLE session_ticket_redemption   TO rmt_definer;
GRANT SELECT, INSERT, UPDATE         ON TABLE tenant                      TO rmt_definer;
GRANT SELECT, INSERT, UPDATE         ON TABLE tenant_branding_pointer     TO rmt_definer;
GRANT SELECT                         ON TABLE tenant_branding_revision    TO rmt_definer;
GRANT SELECT, INSERT, UPDATE         ON TABLE tenant_hostname_assignment  TO rmt_definer;
GRANT SELECT                         ON TABLE tenant_recording_policy     TO rmt_definer;
GRANT SELECT                         ON TABLE tenant_session_policy       TO rmt_definer;
GRANT SELECT, UPDATE                 ON TABLE user_credential_token       TO rmt_definer;
GRANT SELECT, UPDATE                 ON TABLE user_session                TO rmt_definer;
GRANT SELECT                         ON TABLE user_totp                   TO rmt_definer;

-- The table grants it held BEFORE must all be among the ones just granted (same privilege, not grantable); the
-- rest are extras, and a pre-existing role with extras is refused, not trimmed. Then the EFFECTIVE privileges: it
-- must not be able to create in any schema or in this database, by any route (direct grant, PUBLIC, ownership).
DO $$
DECLARE
    r pg_catalog.oid := 'rmt_definer'::pg_catalog.regrole::pg_catalog.oid;
    bad text;
BEGIN
    SELECT pg_catalog.string_agg(s.e, '; ' ORDER BY s.e) INTO bad
    FROM pg_catalog.unnest(pg_catalog.string_to_array(pg_catalog.current_setting('rmt_definer.pre_table_grants', true), E'\n')) s(e)
    WHERE s.e <> '' AND s.e NOT IN (
        SELECT c.relname || ' ' || a.privilege_type || ' ' || a.is_grantable::text
        FROM pg_catalog.pg_class c, pg_catalog.aclexplode(c.relacl) a
        WHERE a.grantee = r AND c.relnamespace = 'public'::pg_catalog.regnamespace AND c.relkind IN ('r', 'p'));
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION '0076: rmt_definer already exists and holds table privileges beyond the grants of this migration (%); revoke them first, this migration does not clean them (docs/22, docs/67)', bad;
    END IF;
    -- REVOKE ALL above runs as the table owner and removes only the OWNER's grants: a privilege some other role
    -- granted to rmt_definer survives it, would be in both snapshots, and pass the comparison. Every table entry it
    -- holds now must come from the table's owner (the GRANT lines) and carry no grant option.
    SELECT pg_catalog.string_agg(c.relname || ' ' || a.privilege_type || ' granted by ' || a.grantor::pg_catalog.regrole::text
                                 || CASE WHEN a.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END, '; '
                                 ORDER BY c.relname, a.privilege_type) INTO bad
    FROM pg_catalog.pg_class c, pg_catalog.aclexplode(c.relacl) a
    WHERE a.grantee = r AND c.relnamespace = 'public'::pg_catalog.regnamespace AND c.relkind IN ('r', 'p')
      AND (a.grantor <> c.relowner OR a.is_grantable);
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION '0076: rmt_definer holds table privileges not granted by this migration (%); revoke them first, this migration does not clean them (docs/22, docs/67)', bad;
    END IF;
    -- EFFECTIVE table and sequence privileges, which also come through PUBLIC (GRANT DELETE ON app_user TO PUBLIC
    -- reaches every role, rmt_definer included, and no check on its own ACL entries sees it): on a table it may have
    -- exactly the privileges its own owner-granted entries name, and on a sequence none at all. Function EXECUTE
    -- via PUBLIC is PostgreSQL's default for every role and gives it nothing anyone else lacks, so it is not checked.
    SELECT pg_catalog.string_agg(c.relname || ' ' || p.priv, '; ' ORDER BY c.relname, p.priv) INTO bad
    FROM pg_catalog.pg_class c
    CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) AS p(priv)
    WHERE c.relnamespace = 'public'::pg_catalog.regnamespace AND c.relkind IN ('r', 'p')
      AND pg_catalog.has_table_privilege(r, c.oid, p.priv)
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(c.relacl) a
                      WHERE a.grantee = r AND a.grantor = c.relowner AND a.privilege_type = p.priv);
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION '0076: rmt_definer can % beyond the grants of this migration (through PUBLIC or another role); revoke that first (docs/22, docs/67)', bad;
    END IF;
    SELECT pg_catalog.string_agg(c.relname || ' ' || p.priv, '; ' ORDER BY c.relname, p.priv) INTO bad
    FROM pg_catalog.pg_class c
    CROSS JOIN (VALUES ('USAGE'), ('SELECT'), ('UPDATE')) AS p(priv)
    WHERE c.relnamespace = 'public'::pg_catalog.regnamespace AND c.relkind = 'S'
      AND pg_catalog.has_sequence_privilege(r, c.oid, p.priv);
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION '0076: rmt_definer can use sequence(s) % (through PUBLIC or another role); it needs none (docs/22, docs/67)', bad;
    END IF;
    -- PUBLIC HYGIENE. Memberships are refused above, so whatever rmt_definer can do beyond its own (checked) entries
    -- comes through PUBLIC. Rather than chase that per object class (columns, views, other schemas, parameters such
    -- as session_replication_role, MAINTAIN on PostgreSQL 17...), refuse ANY PUBLIC privilege beyond PostgreSQL's own
    -- defaults (function EXECUTE, type and language USAGE, database CONNECT/TEMPORARY, USAGE on schema public). Such
    -- a grant reaches rmt_app too, so it is a tenant-isolation defect in its own right, not only a hole in this
    -- boundary. None exists on a normally migrated database.
    SELECT pg_catalog.string_agg(x.e, '; ' ORDER BY x.e) INTO bad FROM (
        SELECT 'relation ' || n.nspname || '.' || c.relname || ' ' || a.privilege_type AS e
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace, pg_catalog.aclexplode(c.relacl) a
        WHERE a.grantee = 0 AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
        UNION ALL
        SELECT 'column ' || n.nspname || '.' || c.relname || '.' || at.attname || ' ' || a.privilege_type
        FROM pg_catalog.pg_attribute at JOIN pg_catalog.pg_class c ON c.oid = at.attrelid
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace, pg_catalog.aclexplode(at.attacl) a
        WHERE a.grantee = 0 AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
        UNION ALL
        SELECT 'schema ' || n.nspname || ' ' || a.privilege_type
        FROM pg_catalog.pg_namespace n, pg_catalog.aclexplode(n.nspacl) a
        WHERE a.grantee = 0 AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
          AND NOT (n.nspname = 'public' AND a.privilege_type = 'USAGE')
        UNION ALL
        SELECT 'database ' || d.datname || ' ' || a.privilege_type
        FROM pg_catalog.pg_database d, pg_catalog.aclexplode(d.datacl) a
        WHERE a.grantee = 0 AND a.privilege_type NOT IN ('CONNECT', 'TEMPORARY')   -- every database: grants are cluster-wide
        UNION ALL
        SELECT 'large object ' || l.oid || ' ' || a.privilege_type
        FROM pg_catalog.pg_largeobject_metadata l, pg_catalog.aclexplode(l.lomacl) a WHERE a.grantee = 0
        UNION ALL
        SELECT 'foreign data wrapper ' || w.fdwname || ' ' || a.privilege_type
        FROM pg_catalog.pg_foreign_data_wrapper w, pg_catalog.aclexplode(w.fdwacl) a WHERE a.grantee = 0
        UNION ALL
        SELECT 'foreign server ' || s.srvname || ' ' || a.privilege_type
        FROM pg_catalog.pg_foreign_server s, pg_catalog.aclexplode(s.srvacl) a WHERE a.grantee = 0
        UNION ALL
        SELECT 'tablespace ' || t.spcname || ' ' || a.privilege_type
        FROM pg_catalog.pg_tablespace t, pg_catalog.aclexplode(t.spcacl) a WHERE a.grantee = 0
    ) x;
    IF pg_catalog.to_regclass('pg_catalog.pg_parameter_acl') IS NOT NULL THEN   -- PostgreSQL 15+
        DECLARE pbad text;
        BEGIN
            EXECUTE 'SELECT pg_catalog.string_agg(''parameter '' || p.parname || '' '' || a.privilege_type, ''; '')
                     FROM pg_catalog.pg_parameter_acl p, pg_catalog.aclexplode(p.paracl) a WHERE a.grantee = 0' INTO pbad;
            IF pbad IS NOT NULL THEN
                bad := COALESCE(bad || '; ', '') || pbad;
            END IF;
        END;
    END IF;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION '0076: PUBLIC holds privileges beyond PostgreSQL''s defaults (%); they reach every role, rmt_definer and rmt_app included; revoke them first (docs/22, docs/67)', bad;
    END IF;
    SELECT pg_catalog.string_agg(n.nspname, ', ' ORDER BY n.nspname) INTO bad
    FROM pg_catalog.pg_namespace n
    WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
      AND pg_catalog.has_schema_privilege('rmt_definer', n.oid, 'CREATE');
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION '0076: rmt_definer can CREATE in schema(s) % (a direct grant, PUBLIC, or ownership); it must have no CREATE anywhere (docs/67)', bad;
    END IF;
    IF pg_catalog.has_database_privilege('rmt_definer', pg_catalog.current_database(), 'CREATE') THEN
        RAISE EXCEPTION '0076: rmt_definer can CREATE in database %; it must not (docs/67)', pg_catalog.current_database();
    END IF;
END
$$;

DO $$
DECLARE
    fn record;
BEGIN
    FOR fn IN
        SELECT n.nspname, p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid) AS args,
               p.proowner::pg_catalog.regrole::text AS owner,
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
        IF NOT fn.ours THEN
            RAISE EXCEPTION '0076: SECURITY DEFINER routine %.%(%) is outside the application''s routines '
                '(another schema, or an extension member); its owner needs a deliberate decision, not this one',
                fn.nspname, fn.proname, fn.args;
        END IF;
        CONTINUE WHEN fn.owner = 'rmt_definer';
        -- ROUTINE, not FUNCTION: a SECURITY DEFINER procedure is owned the same way.
        EXECUTE pg_catalog.format('ALTER ROUTINE %I.%I(%s) OWNER TO rmt_definer', fn.nspname, fn.proname, fn.args);
        RAISE NOTICE '0076: %.%(%) owner % -> rmt_definer', fn.nspname, fn.proname, fn.args, fn.owner;
    END LOOP;
END
$$;
