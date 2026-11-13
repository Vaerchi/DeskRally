-- 0065: nested machine groups (docs/62 stages A+B; review r1 R5/R6).
--
-- machine_group.parent_id has existed since 0001 as a PLAIN single-column FK (ON DELETE SET NULL) that
-- nothing wrote. A plain FK bypasses RLS on write, so as it stood a parent could be another tenant's
-- group, and deleting a parent silently re-rooted its children (changing who can see the subtree).
--
-- This migration makes the tree real and enforces its STRUCTURE in the database. The ACCESS decision
-- stays in Go (GrantFor + GroupScope.Covers): no policy here knows a user or a scope.
--
--   * parent_id becomes the composite FK (tenant_id, parent_id) -> machine_group (tenant_id, id), NO
--     ACTION: no cross-tenant parent; deleting a lone parent that still has children FAILS (never
--     re-roots); a tenant-delete CASCADE that removes parent and children in one statement succeeds
--     because NO ACTION is checked at statement end.
--   * CHECK (parent_id IS DISTINCT FROM id); index on (tenant_id, parent_id).
--   * id and tenant_id are immutable (BEFORE UPDATE guard).
--   * a VOLATILE, SECURITY INVOKER structure trigger takes the per-tenant tree lock FIRST, then walks up
--     from the new parent (cycle -> GT001) and checks depth(new parent) + height(moved subtree) <= 4
--     (depth cap -> GT002); an INSERT's parent must already exist at row time (GT003), which is what makes
--     "an inserted row has no children" true. Under READ COMMITTED each statement in the function takes a fresh snapshot,
--     so after acquiring the lock it sees the committed result of whichever transaction held it before.
--     It runs in the caller's tenant context (RLS shows exactly that tenant's rows, the only legal
--     ancestors); every query also carries an explicit tenant filter.
--   * group_tree_version: one counter per tenant, bumped by every hierarchy mutation (insert, delete,
--     reparent). Grants carry the value they were read at; writes whose authorization depends on the tree
--     (assignment edits, machine moves) are conditional on it being unchanged (Go side).
--   * cp_group_subtree / cp_group_ancestors: tenant-pinned recursive helpers, depth-bounded.

-- ---------------------------------------------------------------------------------------------------
-- The per-tenant tree lock key. Exclusive for hierarchy mutations, shared for the conditional writers.
-- ---------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cp_group_tree_lock_key(p_tenant uuid) RETURNS bigint
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog
AS $$ SELECT pg_catalog.hashtextextended('group_tree:' || p_tenant::text, 0) $$;

-- ---------------------------------------------------------------------------------------------------
-- R6: atomic structure change. Everything below runs in the one transaction the migration runner opens.
-- ---------------------------------------------------------------------------------------------------
LOCK TABLE machine_group IN SHARE ROW EXCLUSIVE MODE;

-- Nothing has ever written parent_id. If a row has one anyway, fail loudly instead of guessing.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM machine_group WHERE parent_id IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 0065: machine_group.parent_id is non-null on existing rows; refusing to adopt an unvalidated hierarchy';
    END IF;
END
$$;

ALTER TABLE machine_group DROP CONSTRAINT machine_group_parent_id_fkey;
ALTER TABLE machine_group
    ADD CONSTRAINT machine_group_parent_fk
    FOREIGN KEY (tenant_id, parent_id) REFERENCES machine_group (tenant_id, id);
ALTER TABLE machine_group
    ADD CONSTRAINT machine_group_not_own_parent CHECK (parent_id IS DISTINCT FROM id);
CREATE INDEX idx_machine_group_parent ON machine_group (tenant_id, parent_id);

-- ---------------------------------------------------------------------------------------------------
-- group_tree_version
-- ---------------------------------------------------------------------------------------------------
CREATE TABLE group_tree_version (
    tenant_id uuid PRIMARY KEY REFERENCES tenant (id) ON DELETE CASCADE,
    version   bigint NOT NULL DEFAULT 0
);

ALTER TABLE group_tree_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_tree_version FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON group_tree_version
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON group_tree_version TO rmt_app;
  END IF;
END $$;

-- Existing tenants that already have groups start at version 0 (a missing row reads as 0 anyway).
INSERT INTO group_tree_version (tenant_id, version)
SELECT DISTINCT tenant_id, 0 FROM machine_group
ON CONFLICT (tenant_id) DO NOTHING;

-- ---------------------------------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------------------------------

-- The roots plus every descendant, as uuid[]. Dangling roots contribute nothing (a safe deny). The empty
-- array it returns for an empty/NULL input is NOT "tenant-wide": callers decide that from the stored
-- scope, never from this result.
CREATE OR REPLACE FUNCTION cp_group_subtree(p_tenant uuid, p_roots uuid[]) RETURNS uuid[]
LANGUAGE sql STABLE
SET search_path = pg_catalog, public
AS $$
    WITH RECURSIVE sub(id, depth) AS (
        SELECT g.id, 1
          FROM public.machine_group g
         WHERE g.tenant_id = p_tenant AND g.id = ANY (p_roots)
        UNION ALL
        SELECT c.id, sub.depth + 1
          FROM public.machine_group c
          JOIN sub ON c.parent_id = sub.id
         WHERE c.tenant_id = p_tenant AND sub.depth < 8
    )
    SELECT COALESCE(array_agg(DISTINCT id), '{}'::uuid[]) FROM sub
$$;

-- The group and its ancestors, nearest first (self, parent, ..., root). Empty for an unknown group.
CREATE OR REPLACE FUNCTION cp_group_ancestors(p_tenant uuid, p_group uuid) RETURNS uuid[]
LANGUAGE sql STABLE
SET search_path = pg_catalog, public
AS $$
    WITH RECURSIVE up(id, parent_id, depth) AS (
        SELECT g.id, g.parent_id, 1
          FROM public.machine_group g
         WHERE g.tenant_id = p_tenant AND g.id = p_group
        UNION ALL
        SELECT g.id, g.parent_id, up.depth + 1
          FROM public.machine_group g
          JOIN up ON g.id = up.parent_id
         WHERE g.tenant_id = p_tenant AND up.depth < 8
    )
    SELECT COALESCE(array_agg(id ORDER BY depth), '{}'::uuid[]) FROM up
$$;

-- ---------------------------------------------------------------------------------------------------
-- Triggers
-- ---------------------------------------------------------------------------------------------------

-- R5: id and tenant_id are immutable.
CREATE OR REPLACE FUNCTION machine_group_guard_keys() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        RAISE EXCEPTION 'machine_group id and tenant_id are immutable'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER machine_group_guard_keys
    BEFORE UPDATE ON machine_group
    FOR EACH ROW EXECUTE FUNCTION machine_group_guard_keys();

-- The structure check. Lock first (so two concurrent reparents cannot each pass in isolation and together
-- form a cycle), then read.
CREATE OR REPLACE FUNCTION machine_group_check_structure() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    parent_level int;
    cyc          boolean;
    height       int;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(public.cp_group_tree_lock_key(NEW.tenant_id));
    IF NEW.parent_id IS NULL THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.parent_id IS NOT DISTINCT FROM OLD.parent_id THEN
        RETURN NEW;
    END IF;

    -- An INSERT assumes the new row has no children (height 1 below), which holds only if its parent
    -- ALREADY exists: a multi-row INSERT with explicit ids in leaf-to-root order would otherwise build a
    -- chain whose parents arrive after their children, never re-checked (the statement-end FK passes).
    -- Rows inserted earlier in the same statement are visible to this VOLATILE function, so a root-first
    -- multi-row insert still works. GT003 = "the parent group must exist first".
    IF TG_OP = 'INSERT' AND NOT EXISTS (
        SELECT 1 FROM public.machine_group p
         WHERE p.tenant_id = NEW.tenant_id AND p.id = NEW.parent_id
    ) THEN
        RAISE EXCEPTION 'machine_group: the parent group must exist first' USING ERRCODE = 'GT003';
    END IF;

    -- Walk up from the new parent: its level (a root is level 1) and whether it reaches this row.
    WITH RECURSIVE up(id, parent_id, depth) AS (
        SELECT g.id, g.parent_id, 1
          FROM public.machine_group g
         WHERE g.tenant_id = NEW.tenant_id AND g.id = NEW.parent_id
        UNION ALL
        SELECT g.id, g.parent_id, up.depth + 1
          FROM public.machine_group g
          JOIN up ON g.id = up.parent_id
         WHERE g.tenant_id = NEW.tenant_id AND up.depth < 16
    )
    SELECT COALESCE(max(depth), 0), COALESCE(bool_or(id = NEW.id), false)
      INTO parent_level, cyc
      FROM up;

    IF cyc THEN
        RAISE EXCEPTION 'machine_group: this move would create a cycle' USING ERRCODE = 'GT001';
    END IF;

    -- Height of the moved subtree (this row alone = 1; an INSERT has no children yet).
    height := 1;
    IF TG_OP = 'UPDATE' THEN
        WITH RECURSIVE down(id, depth) AS (
            SELECT NEW.id, 1
            UNION ALL
            SELECT c.id, down.depth + 1
              FROM public.machine_group c
              JOIN down ON c.parent_id = down.id
             WHERE c.tenant_id = NEW.tenant_id AND down.depth < 16
        )
        SELECT max(depth) INTO height FROM down;
    END IF;

    IF parent_level + height > 4 THEN
        RAISE EXCEPTION 'machine_group: subgroups nest at most 4 levels' USING ERRCODE = 'GT002';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER machine_group_check_structure
    BEFORE INSERT OR UPDATE OF parent_id ON machine_group
    FOR EACH ROW EXECUTE FUNCTION machine_group_check_structure();

-- A delete is a hierarchy mutation too: serialize it with the others.
CREATE OR REPLACE FUNCTION machine_group_lock_on_delete() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(public.cp_group_tree_lock_key(OLD.tenant_id));
    RETURN OLD;
END;
$$;

CREATE TRIGGER machine_group_lock_on_delete
    BEFORE DELETE ON machine_group
    FOR EACH ROW EXECUTE FUNCTION machine_group_lock_on_delete();

-- Bump the tenant's tree version on every insert / delete / reparent. A delete only UPDATEs (never
-- INSERTs): during a tenant-delete cascade the tenant row is going away and an INSERT here would fail
-- its FK; an existing row simply gets bumped or has already been cascaded.
CREATE OR REPLACE FUNCTION machine_group_bump_version() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        UPDATE public.group_tree_version SET version = version + 1 WHERE tenant_id = OLD.tenant_id;
        RETURN OLD;
    END IF;
    INSERT INTO public.group_tree_version (tenant_id, version) VALUES (NEW.tenant_id, 1)
    ON CONFLICT (tenant_id) DO UPDATE SET version = public.group_tree_version.version + 1;
    RETURN NEW;
END;
$$;

CREATE TRIGGER machine_group_bump_version
    AFTER INSERT OR DELETE OR UPDATE OF parent_id ON machine_group
    FOR EACH ROW EXECUTE FUNCTION machine_group_bump_version();

COMMENT ON COLUMN machine_group.parent_id IS
    'docs/62: nesting. Composite FK (tenant_id, parent_id), NO ACTION (a parent with children cannot be '
    'deleted); cycles and depth > 4 refused by machine_group_check_structure. Access inherits DOWNWARD '
    '(a scope on a parent covers its descendants) - decided in Go, not here.';
