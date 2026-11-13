-- 0075: the Owner can be told a publication was WITHDRAWN (docs/66 2j, 2l).
--
-- WHAT. 0071/0072 record WHEN an approval happened (tenant_branding_pointer.published_at) but a withdrawal only
-- cleared the published columns, so the pointer could not tell "an operator withdrew it" from "never approved".
-- The facts were in the tenant's audit chain, but that carries the operator and the reason (which a tenant must
-- not read, 2a.3), so the pointer now records the two facts the Owner may see:
--
--   withdrawn_at           when the operator withdrew the last publication
--   withdrawn_revision_id  which revision that was (NULL when not known: a backfilled row whose approval event
--                          does not name a revision that still exists)
--
-- RULES. cp_platform_branding_withdraw sets both after clearing; cp_platform_branding_approve clears them (a
-- new publication supersedes the withdrawal); cp_hostname_clear_published (assign, release, reactivate) clears
-- them too: an approval is bound to ONE assignment, so a new hostname starts as "never approved" (2a.10).
-- rmt_app already holds SELECT on the whole pointer row and still cannot write these columns.
--
-- BACKFILL, honest: a pointer with nothing published whose LATEST branding or hostname audit event on the
-- tenant's chain is a withdrawal gets withdrawn_at = that event's time, and withdrawn_revision_id = the revision
-- named by the LATEST earlier approval event (that event is chosen first, whether or not its revision still
-- exists or its metadata is usable; only then is its revision resolved against the same tenant, and
-- withdrawn_revision_id stays NULL if it cannot be). An older surviving approval is never substituted. Anything else
-- (never approved, cleared by a hostname change, no audit row) stays NULL: unknown is never invented.
--
-- COST. tenant_branding_pointer has ONE row per tenant (tenant_id is its PRIMARY KEY), so the backfill UPDATE writes
-- at most one row per tenant. The RUNTIME is not bounded by that: the backfill reads the audit chain (the latest
-- branding/hostname event per tenant, then the latest earlier approval) and the new constraints are validated, both
-- data-dependent. The migration runs in one transaction, so the ALTER TABLE lock on the pointer table is held until
-- it commits: approvals, withdrawals and hostname changes wait for it (the deploy's migrate step uses lock_timeout).
--
-- ROLLBACK. Additive: DROP the two columns and the constraint, restore 0072's three functions.

ALTER TABLE tenant_branding_pointer ADD COLUMN IF NOT EXISTS withdrawn_at timestamptz;
ALTER TABLE tenant_branding_pointer ADD COLUMN IF NOT EXISTS withdrawn_revision_id uuid;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tenant_branding_pointer_withdrawn_revision_fkey') THEN
        ALTER TABLE tenant_branding_pointer
            ADD CONSTRAINT tenant_branding_pointer_withdrawn_revision_fkey
            FOREIGN KEY (tenant_id, withdrawn_revision_id) REFERENCES tenant_branding_revision (tenant_id, id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tenant_branding_pointer_withdrawn_shape') THEN
        -- a withdrawal needs a time, never coexists with a publication, and a revision id needs a withdrawal
        ALTER TABLE tenant_branding_pointer
            ADD CONSTRAINT tenant_branding_pointer_withdrawn_shape CHECK (
                (withdrawn_at IS NULL AND withdrawn_revision_id IS NULL) OR
                (withdrawn_at IS NOT NULL AND published_revision_id IS NULL));
    END IF;
END
$$;

-- backfill (see above)
UPDATE tenant_branding_pointer p
   SET withdrawn_at = w.occurred_at,
       withdrawn_revision_id = (
           SELECT r.id
             FROM (SELECT ap.metadata
                     FROM audit_event ap
                    WHERE ap.tenant_id = p.tenant_id AND ap.action = 'tenant.branding.approve'
                      AND (ap.occurred_at, ap.seq) < (w.occurred_at, w.seq)
                    ORDER BY ap.occurred_at DESC, ap.seq DESC
                    LIMIT 1) la
             JOIN tenant_branding_revision r
               ON r.tenant_id = p.tenant_id AND r.id::text = la.metadata ->> 'revision_id')
  FROM (SELECT DISTINCT ON (tenant_id) tenant_id, action, occurred_at, seq
          FROM audit_event
         WHERE seq IS NOT NULL
           AND (action IN ('tenant.branding.approve', 'tenant.branding.withdraw') OR action LIKE 'tenant.hostname.%')
         ORDER BY tenant_id, occurred_at DESC, seq DESC) w
 WHERE w.tenant_id = p.tenant_id AND w.action = 'tenant.branding.withdraw'
   AND p.published_revision_id IS NULL AND p.withdrawn_at IS NULL;

-- A hostname change clears the withdrawal record with the publication (redefined from 0072, the latest).
CREATE OR REPLACE FUNCTION cp_hostname_clear_published(p_tenant uuid) RETURNS void
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    UPDATE public.tenant_branding_pointer
       SET published_revision_id = NULL, published_revision_hash = NULL, published_assignment_id = NULL,
           published_by = NULL, published_at = NULL, withdrawn_at = NULL, withdrawn_revision_id = NULL,
           review_generation = review_generation + 1
     WHERE tenant_id = p_tenant
$$;

-- Approval clears the withdrawal record (redefined from 0072, the latest).
CREATE OR REPLACE FUNCTION cp_platform_branding_approve(p_user uuid, p_session uuid, p_tenant uuid, p_revision uuid,
                                                         p_hash text, p_assignment uuid, p_generation bigint, p_by text)
    RETURNS TABLE (revision_id uuid, normalized_hash text, assignment_id uuid, assignment_host text,
                   assignment_state text, product_name text)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    PERFORM public.cp_platform_check(p_user, p_session, interval '15 minutes');
    PERFORM set_config('lock_timeout', '5000', true);
    PERFORM public.cp_hostname_lock_tenant(p_tenant);          -- P0002 for an unknown tenant; takes the pointer-row lock
    RETURN QUERY
        UPDATE public.tenant_branding_pointer p
           SET published_revision_id = r.id, published_revision_hash = r.normalized_hash,
               published_assignment_id = a.id, published_by = p_by, published_at = now(),
               withdrawn_at = NULL, withdrawn_revision_id = NULL,
               review_generation = p.review_generation + 1
          FROM public.tenant_branding_revision r, public.tenant_hostname_assignment a
         WHERE p.tenant_id = p_tenant
           AND p.draft_revision_id = p_revision
           AND p.review_generation = p_generation
           AND r.tenant_id = p_tenant AND r.id = p_revision AND r.normalized_hash = p_hash
           AND a.tenant_id = p_tenant AND a.id = p_assignment AND a.state IN ('pending', 'active')
        RETURNING r.id, r.normalized_hash, a.id, a.host, a.state, r.product_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'branding: review is stale' USING ERRCODE = 'HS002';
    END IF;
END
$$;

-- Withdrawal records when and which (redefined from 0072, the latest).
CREATE OR REPLACE FUNCTION cp_platform_branding_withdraw(p_user uuid, p_session uuid, p_tenant uuid)
    RETURNS void
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_rev uuid;
BEGIN
    PERFORM public.cp_platform_check(p_user, p_session, interval '15 minutes');
    PERFORM set_config('lock_timeout', '5000', true);
    PERFORM public.cp_hostname_lock_tenant(p_tenant);
    SELECT p.published_revision_id INTO v_rev
      FROM public.tenant_branding_pointer p WHERE p.tenant_id = p_tenant AND p.published_revision_id IS NOT NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'branding: nothing is published' USING ERRCODE = 'HS003';
    END IF;
    PERFORM public.cp_hostname_clear_published(p_tenant);
    UPDATE public.tenant_branding_pointer
       SET withdrawn_at = now(), withdrawn_revision_id = v_rev
     WHERE tenant_id = p_tenant;
END
$$;
