-- 0072: per-tenant hostname theming, stage 1b (docs/66 sections 2a.3, 2a.6, 2b.2, 2b.7, 2c.2, 2d.1).
--
-- WHAT. Branding revision PUBLICATION, on top of the shape 0071 shipped:
--
--   1. Two integrity constraints that 0071 left to the application: the published pointer's HASH must be the
--      hash of the revision it points at (a composite foreign key through (tenant_id, id, normalized_hash)),
--      and a revision's logo hash must be the SHA-256 of its logo bytes (the built-in sha256(bytea)). Both
--      tables are empty when this runs: stage 1a wrote nothing to them.
--   2. cp_public_branding_lookup(host, want_logo): THE public read. ONE statement, the same for every host:
--      host -> its ACTIVE assignment -> tenant not disabled -> the tenant's pointer whose published assignment
--      id EQUALS that assignment -> the revision whose hash EQUALS the published hash. It returns a row or no
--      row and the application branches only on that. It is pre-tenant (SECURITY DEFINER, like
--      cp_resolve_tenant_by_slug) and returns no tenant id, no revision id and no assignment id.
--   3. The operator functions: cp_platform_branding_review (the draft revision exactly as stored, with the
--      pointer and assignment facts), cp_platform_branding_peers (other tenants' published names, for the
--      confusable check), cp_platform_branding_approve (the COMPARE-AND-SWAP: tenant, draft revision id,
--      revision hash and the tenant's current live assignment id, all evaluated under the tenant's
--      pointer-row lock) and cp_platform_branding_withdraw. All sit behind cp_platform_check, the same gate
--      every platform mutation uses, and take cp_hostname_lock_tenant first, the same lock the Owner's edit
--      and every assignment change take, so edit, approve, withdraw, assign, activate, release and reactivate
--      are totally ordered per tenant (docs/66 2b.2).
--
-- WHY NOT LET THE APPLICATION ROLE PUBLISH. rmt_app holds INSERT/SELECT on revisions and may move only the
-- DRAFT pointer (0071). The published columns are writable only through cp_platform_branding_approve and
-- withdraw, so no Owner credential, SQL injection in a tenant-scoped path or bug in a console handler can
-- publish: publication is an operator act in the database, not a branch in a handler.
--
-- ROLLBACK. Additive: DROP the five functions and the two constraints; 0071's shape is untouched.

-- 1a. the REVIEW GENERATION (docs/66 2b.2, repair A1). The CAS predicates (draft id, hash, assignment id) are all
-- unchanged by a withdrawal, so an approval prepared BEFORE a withdrawal could take the lock afterwards and
-- republish the withdrawn brand. The pointer row therefore carries a generation the operator's review returns and
-- the approval must send back; it is compared under the pointer lock. It moves on EVERY review-invalidating change:
-- a new draft, an approval, a withdrawal (the trigger below: any change of the draft or published revision), and
-- assign, release and reactivate (cp_hostname_clear_published, redefined here, bumps explicitly because it may
-- clear nothing). Activation does not move it (an approval made while pending must survive activation, 2c.2).
ALTER TABLE tenant_branding_pointer ADD COLUMN IF NOT EXISTS review_generation bigint NOT NULL DEFAULT 0;

CREATE OR REPLACE FUNCTION tenant_branding_pointer_generation() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    IF NEW.review_generation = OLD.review_generation AND
       (NEW.draft_revision_id IS DISTINCT FROM OLD.draft_revision_id OR
        NEW.published_revision_id IS DISTINCT FROM OLD.published_revision_id) THEN
        NEW.review_generation := OLD.review_generation + 1;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS tenant_branding_pointer_generation ON tenant_branding_pointer;
CREATE TRIGGER tenant_branding_pointer_generation
    BEFORE UPDATE ON tenant_branding_pointer
    FOR EACH ROW EXECUTE FUNCTION tenant_branding_pointer_generation();

CREATE OR REPLACE FUNCTION cp_hostname_clear_published(p_tenant uuid) RETURNS void
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    UPDATE public.tenant_branding_pointer
       SET published_revision_id = NULL, published_revision_hash = NULL, published_assignment_id = NULL,
           published_by = NULL, published_at = NULL, review_generation = review_generation + 1
     WHERE tenant_id = p_tenant
$$;

-- 1. integrity ---------------------------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tenant_branding_revision_tenant_id_id_hash_key') THEN
        ALTER TABLE tenant_branding_revision
            ADD CONSTRAINT tenant_branding_revision_tenant_id_id_hash_key UNIQUE (tenant_id, id, normalized_hash);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tenant_branding_pointer_published_hash_fkey') THEN
        ALTER TABLE tenant_branding_pointer
            ADD CONSTRAINT tenant_branding_pointer_published_hash_fkey
            FOREIGN KEY (tenant_id, published_revision_id, published_revision_hash)
            REFERENCES tenant_branding_revision (tenant_id, id, normalized_hash);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tenant_branding_revision_logo_hash') THEN
        ALTER TABLE tenant_branding_revision
            ADD CONSTRAINT tenant_branding_revision_logo_hash
            CHECK (logo_png IS NULL OR logo_sha256 = encode(sha256(logo_png), 'hex'));
    END IF;
END
$$;

-- 2. the public read ---------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION cp_public_branding_lookup(p_host text, p_want_logo boolean)
    RETURNS TABLE (product_name text, accent_color text, support_text text,
                   support_contact_kind text, support_contact_value text, logo_sha256 text, logo_png bytea)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT r.product_name, r.accent_color, r.support_text, r.support_contact_kind, r.support_contact_value,
           r.logo_sha256, CASE WHEN p_want_logo THEN r.logo_png END
      FROM public.tenant_hostname_assignment a
      JOIN public.tenant t                    ON t.id = a.tenant_id AND t.disabled_at IS NULL
      JOIN public.tenant_branding_pointer p   ON p.tenant_id = a.tenant_id AND p.published_assignment_id = a.id
      JOIN public.tenant_branding_revision r  ON r.tenant_id = p.tenant_id AND r.id = p.published_revision_id
                                             AND r.normalized_hash = p.published_revision_hash
     WHERE a.host = p_host AND a.state = 'active'
$$;

-- 3. the operator functions --------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION cp_platform_branding_review(p_user uuid, p_session uuid, p_tenant uuid)
    RETURNS TABLE (revision_id uuid, seq bigint, product_name text, accent_color text, support_text text,
                   support_contact_kind text, support_contact_value text, logo_sha256 text, logo_png bytea,
                   normalized_hash text, created_by text, created_at timestamptz,
                   published_revision_id uuid, published_revision_hash text, published_assignment_id uuid,
                   assignment_id uuid, assignment_host text, assignment_state text, review_generation bigint)
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    PERFORM public.cp_platform_check(p_user, p_session, interval '12 hours');
    IF NOT EXISTS (SELECT 1 FROM public.tenant t WHERE t.id = p_tenant) THEN
        RAISE EXCEPTION 'hostname: no such tenant' USING ERRCODE = 'P0002';
    END IF;
    RETURN QUERY
        SELECT d.id, d.seq, d.product_name, d.accent_color, d.support_text, d.support_contact_kind,
               d.support_contact_value, d.logo_sha256, d.logo_png, d.normalized_hash, d.created_by, d.created_at,
               p.published_revision_id, p.published_revision_hash, p.published_assignment_id,
               a.id, a.host, a.state, COALESCE(p.review_generation, 0)
          FROM public.tenant t
          LEFT JOIN public.tenant_branding_pointer p  ON p.tenant_id = t.id
          LEFT JOIN public.tenant_branding_revision d ON d.tenant_id = t.id AND d.id = p.draft_revision_id
          LEFT JOIN public.tenant_hostname_assignment a ON a.tenant_id = t.id AND a.state IN ('pending', 'active')
         WHERE t.id = p_tenant;
END
$$;

CREATE OR REPLACE FUNCTION cp_platform_branding_peers(p_user uuid, p_session uuid)
    RETURNS TABLE (tenant_id uuid, product_name text)
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    PERFORM public.cp_platform_check(p_user, p_session, interval '12 hours');
    RETURN QUERY
        SELECT p.tenant_id, r.product_name
          FROM public.tenant_branding_pointer p
          JOIN public.tenant_branding_revision r ON r.tenant_id = p.tenant_id AND r.id = p.published_revision_id
          JOIN public.tenant_hostname_assignment a ON a.id = p.published_assignment_id AND a.state IN ('pending', 'active')
         ORDER BY p.tenant_id;
END
$$;

-- The compare-and-swap. SQLSTATE HS002 = stale review (nothing published).
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

CREATE OR REPLACE FUNCTION cp_platform_branding_withdraw(p_user uuid, p_session uuid, p_tenant uuid)
    RETURNS void
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    PERFORM public.cp_platform_check(p_user, p_session, interval '15 minutes');
    PERFORM set_config('lock_timeout', '5000', true);
    PERFORM public.cp_hostname_lock_tenant(p_tenant);
    IF NOT EXISTS (SELECT 1 FROM public.tenant_branding_pointer p WHERE p.tenant_id = p_tenant AND p.published_revision_id IS NOT NULL) THEN
        RAISE EXCEPTION 'branding: nothing is published' USING ERRCODE = 'HS003';
    END IF;
    PERFORM public.cp_hostname_clear_published(p_tenant);
END
$$;
