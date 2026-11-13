-- 0071: per-tenant hostname theming, stage 1a (docs/66 sections 2a.1, 2a.10, 2b.2, 2b.5, 2c.2, 2f).
--
-- WHAT. Four things, all additive and forward-only:
--
--   1. tenant_hostname_assignment: the operator-managed hostname table, as an assignment HISTORY. A row is one
--      tenant holding one host for one period. Rows are never deleted by the application. Release is terminal
--      for a row; "reactivate" creates a NEW row (so a new assignment id), which is what makes a stale
--      branding approval stop matching (docs/66 2c.2). pending -> active keeps the same id.
--   2. tenant_branding_revision + tenant_branding_pointer: the immutable branding revision ledger and the
--      tenant's draft/published pointer, with TENANT-QUALIFIED composite foreign keys (docs/66 2b.2). Stage 1a
--      ships the SHAPE only (nothing writes a revision yet); stage 1b adds the editing and approval paths. The
--      published pointer is a triple: revision id, the revision's hash, and the assignment id the operator
--      approved against (2c.2).
--   3. cp_platform_hostname_*: the operator lifecycle (assign, activate, release, reactivate, list) as SECURITY
--      DEFINER functions behind cp_platform_check, the same gate every other platform mutation uses. The
--      application writes the audit trail around them in the same transaction (platform.go).
--   4. cp_attended_redeem_scoped: the redeem lookup with the HOST scope pushed into the same statement that
--      takes the row lock (2a.1). cp_attended_redeem becomes a one-line wrapper (unscoped), so a rolled-back
--      Go binary still works against this schema.
--
-- QUARANTINE (2a.10) is enforced where the rows are written, not in a handler: the BEFORE trigger below takes
-- a per-host advisory lock and refuses to create or activate an assignment for a host that a DIFFERENT tenant
-- released less than its quarantined_until ago. Every path (the platform API, a CLI, an importer, a test seed)
-- goes through that trigger. A CHECK additionally requires a released row to carry at least 30 days of
-- quarantine, so a direct INSERT cannot mint a released row with no delay. The same tenant may take its own
-- host back during quarantine (the quarantine exists so nobody ELSE inherits old links); that is still a NEW
-- assignment id. The delay is a delay: after the deadline a different tenant may be assigned the host.
--
-- Redefinition note (standing rule: redefine a function from its LATEST definition). The body of
-- cp_attended_redeem_scoped is the body of 0021 (the latest definition; 0022/0036/0042/0052/0059 do not
-- redefine it) with EXACTLY two additions: the host-scope predicate, and the bounded lock wait. Every other
-- predicate (pending, unexpired, tenant not disabled, row lock) is kept.

-- ---------------------------------------------------------------------------------------------------
-- 1. Assignment history
-- ---------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant_hostname_assignment (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    host              text        NOT NULL
        CONSTRAINT tenant_hostname_assignment_host_format CHECK (
            host = lower(host) AND char_length(host) <= 253
            AND host ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'),
    tenant_id         uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    kind              text        NOT NULL DEFAULT 'subdomain' CHECK (kind IN ('subdomain', 'custom')),
    state             text        NOT NULL DEFAULT 'pending'   CHECK (state IN ('pending', 'active', 'released')),
    created_by        text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 200),
    created_at        timestamptz NOT NULL DEFAULT now(),
    activated_at      timestamptz,
    released_at       timestamptz,
    released_by       text        CHECK (released_by IS NULL OR char_length(released_by) BETWEEN 1 AND 200),
    quarantined_until timestamptz,
    CONSTRAINT tenant_hostname_assignment_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT tenant_hostname_assignment_state_shape CHECK (
        (state = 'pending'  AND activated_at IS NULL     AND released_at IS NULL     AND quarantined_until IS NULL) OR
        (state = 'active'   AND activated_at IS NOT NULL AND released_at IS NULL     AND quarantined_until IS NULL) OR
        (state = 'released' AND released_at IS NOT NULL  AND released_by IS NOT NULL AND quarantined_until IS NOT NULL
                            AND quarantined_until - released_at >= interval '30 days'))
);

-- One live (pending or active) assignment per host, and (v1) one per tenant. These two indexes are what make a
-- concurrent double-assign produce exactly one winner under any interleaving.
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_hostname_live_host
    ON tenant_hostname_assignment (host) WHERE state IN ('pending', 'active');
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_hostname_live_tenant
    ON tenant_hostname_assignment (tenant_id) WHERE state IN ('pending', 'active');
CREATE INDEX IF NOT EXISTS idx_tenant_hostname_history
    ON tenant_hostname_assignment (host, created_at DESC);

ALTER TABLE tenant_hostname_assignment ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_hostname_assignment FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_read ON tenant_hostname_assignment;
-- A tenant may READ its own rows (the console shows its public address); nobody but a definer function writes.
CREATE POLICY tenant_read ON tenant_hostname_assignment FOR SELECT
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

CREATE OR REPLACE FUNCTION tenant_hostname_assignment_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_release_time timestamptz;
BEGIN
    -- EVERY write path (API function, CLI, importer, seed, direct SQL) serializes per host here, first.
    PERFORM pg_advisory_xact_lock(hashtextextended('tenant_hostname:' || NEW.host, 0));

    IF TG_OP = 'UPDATE' THEN
        -- Identity columns never change; released is terminal; the only transitions are
        -- pending -> active, pending -> released, active -> released.
        IF NEW.id <> OLD.id OR NEW.host <> OLD.host OR NEW.tenant_id <> OLD.tenant_id
           OR NEW.created_at <> OLD.created_at OR NEW.created_by <> OLD.created_by OR NEW.kind <> OLD.kind THEN
            RAISE EXCEPTION 'tenant_hostname_assignment: identity columns are immutable' USING ERRCODE = '23514';
        END IF;
        IF OLD.state = 'released' THEN
            RAISE EXCEPTION 'tenant_hostname_assignment: a released assignment is immutable (reactivation creates a new row)'
                USING ERRCODE = '23514';
        END IF;
        IF OLD.state = 'active' AND NEW.state = 'pending' THEN
            RAISE EXCEPTION 'tenant_hostname_assignment: an active assignment cannot return to pending' USING ERRCODE = '23514';
        END IF;
    END IF;

    -- A release is stamped HERE, on every path, including a row INSERTED already released: the release time is
    -- the database clock (a caller-supplied value is overwritten, never trusted) and the quarantine may not be
    -- shorter than 720 hours from it. A caller may ask for LONGER; asking for less is refused.
    -- The clock is clock_timestamp() read AFTER the advisory lock above, NOT now(): now() is the TRANSACTION start,
    -- so a long transaction would release with an already-expired quarantine and one delayed on the lock would get
    -- a shortened one. One value stamps released_at and bounds quarantined_until.
    IF NEW.state = 'released' AND (TG_OP = 'INSERT' OR OLD.state <> 'released') THEN
        v_release_time := clock_timestamp();
        NEW.released_at := v_release_time;
        IF NEW.quarantined_until IS NULL THEN
            NEW.quarantined_until := v_release_time + interval '720 hours';
        ELSIF NEW.quarantined_until < v_release_time + interval '720 hours' THEN
            RAISE EXCEPTION 'tenant_hostname_assignment: quarantine is at least 720 hours from the release' USING ERRCODE = '23514';
        END IF;
    END IF;

    -- Creating or activating: refuse while ANOTHER tenant's release is quarantined.
    IF NEW.state IN ('pending', 'active') AND (TG_OP = 'INSERT' OR OLD.state = 'pending') THEN
        IF EXISTS (SELECT 1 FROM public.tenant_hostname_assignment q
                    WHERE q.host = NEW.host AND q.id <> NEW.id AND q.tenant_id <> NEW.tenant_id
                      AND q.state = 'released' AND q.quarantined_until > clock_timestamp()) THEN
            RAISE EXCEPTION 'hostname is quarantined' USING ERRCODE = 'HQ001';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS tenant_hostname_assignment_guard ON tenant_hostname_assignment;
CREATE TRIGGER tenant_hostname_assignment_guard
    BEFORE INSERT OR UPDATE ON tenant_hostname_assignment
    FOR EACH ROW EXECUTE FUNCTION tenant_hostname_assignment_guard();

-- The application role reads its own rows through RLS and writes through the definer functions only.
REVOKE ALL ON tenant_hostname_assignment FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        REVOKE ALL ON tenant_hostname_assignment FROM rmt_app;
        GRANT SELECT ON tenant_hostname_assignment TO rmt_app;
    END IF;
END
$$;

-- ---------------------------------------------------------------------------------------------------
-- 2. Branding revisions and the published pointer (shape for stage 1b)
-- ---------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant_branding_revision (
    id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    seq                   bigint      NOT NULL CHECK (seq > 0),
    product_name          text        NOT NULL DEFAULT '' CHECK (char_length(product_name) <= 100),
    accent_color          text        NOT NULL DEFAULT '' CHECK (accent_color = '' OR accent_color ~ '^#[0-9a-f]{6}$'),
    support_text          text        NOT NULL DEFAULT '' CHECK (char_length(support_text) <= 280),
    support_contact_kind  text        NOT NULL DEFAULT '' CHECK (support_contact_kind IN ('', 'phone', 'email', 'url')),
    support_contact_value text        NOT NULL DEFAULT '' CHECK (char_length(support_contact_value) <= 200),
    logo_sha256           text        NOT NULL DEFAULT '',
    logo_png              bytea,
    normalized_hash       text        NOT NULL CHECK (normalized_hash ~ '^[0-9a-f]{64}$'),
    created_by            text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 200),
    created_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tenant_branding_revision_tenant_id_id_key  UNIQUE (tenant_id, id),
    CONSTRAINT tenant_branding_revision_tenant_id_seq_key UNIQUE (tenant_id, seq),
    CONSTRAINT tenant_branding_revision_logo_shape CHECK (
        (logo_sha256 = '' AND logo_png IS NULL) OR
        (logo_sha256 ~ '^[0-9a-f]{64}$' AND logo_png IS NOT NULL AND octet_length(logo_png) <= 65536)),
    CONSTRAINT tenant_branding_revision_contact_shape CHECK (
        (support_contact_kind = '' AND support_contact_value = '') OR
        (support_contact_kind <> '' AND support_contact_value <> ''))
);

CREATE OR REPLACE FUNCTION tenant_branding_revision_immutable() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'tenant_branding_revision rows are immutable (insert a new revision)' USING ERRCODE = '23514';
END
$$;

DROP TRIGGER IF EXISTS tenant_branding_revision_immutable ON tenant_branding_revision;
CREATE TRIGGER tenant_branding_revision_immutable
    BEFORE UPDATE ON tenant_branding_revision
    FOR EACH ROW EXECUTE FUNCTION tenant_branding_revision_immutable();

ALTER TABLE tenant_branding_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_branding_revision FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_branding_revision;
CREATE POLICY tenant_isolation ON tenant_branding_revision
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- The published pointer. EVERY reference is composite (tenant_id, x): a plain foreign key on x alone bypasses
-- RLS on write and would let a pointer name another tenant's revision or assignment (docs/66 2b.2).
CREATE TABLE IF NOT EXISTS tenant_branding_pointer (
    tenant_id                uuid        PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
    draft_revision_id        uuid,
    published_revision_id    uuid,
    published_revision_hash  text        CHECK (published_revision_hash IS NULL OR published_revision_hash ~ '^[0-9a-f]{64}$'),
    published_assignment_id  uuid,
    published_by             text,
    published_at             timestamptz,
    FOREIGN KEY (tenant_id, draft_revision_id)     REFERENCES tenant_branding_revision (tenant_id, id),
    FOREIGN KEY (tenant_id, published_revision_id) REFERENCES tenant_branding_revision (tenant_id, id),
    FOREIGN KEY (tenant_id, published_assignment_id) REFERENCES tenant_hostname_assignment (tenant_id, id),
    CONSTRAINT tenant_branding_pointer_published_all_or_none CHECK (
        (published_revision_id IS NULL AND published_revision_hash IS NULL AND published_assignment_id IS NULL
            AND published_by IS NULL AND published_at IS NULL) OR
        (published_revision_id IS NOT NULL AND published_revision_hash IS NOT NULL AND published_assignment_id IS NOT NULL
            AND published_by IS NOT NULL AND published_at IS NOT NULL))
);

ALTER TABLE tenant_branding_pointer ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_branding_pointer FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_branding_pointer;
CREATE POLICY tenant_isolation ON tenant_branding_pointer
    USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid);

-- An Owner may append revisions and move ITS OWN draft pointer. It can never write the published triple (that
-- is the operator's approval, through a definer function in stage 1b): column-level grants, not a policy.
REVOKE ALL ON tenant_branding_revision FROM PUBLIC;
REVOKE ALL ON tenant_branding_pointer  FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        REVOKE ALL ON tenant_branding_revision FROM rmt_app;
        REVOKE ALL ON tenant_branding_pointer  FROM rmt_app;
        GRANT SELECT, INSERT ON tenant_branding_revision TO rmt_app;
        GRANT SELECT ON tenant_branding_pointer TO rmt_app;
        GRANT INSERT (tenant_id, draft_revision_id) ON tenant_branding_pointer TO rmt_app;
        GRANT UPDATE (draft_revision_id)            ON tenant_branding_pointer TO rmt_app;
    END IF;
END
$$;

-- ---------------------------------------------------------------------------------------------------
-- 3. Operator lifecycle (SECURITY DEFINER, behind cp_platform_check)
-- ---------------------------------------------------------------------------------------------------
-- Lock order for every function here: the tenant's branding pointer row (created on demand so the lock target
-- always exists), THEN the per-host advisory lock (taken by the trigger), then assignment rows. A fixed order
-- means no deadlock between assign / activate / release / reactivate (docs/66 2b.2).
-- Error codes the application maps: 42501 not an operator; P0002 no such tenant/assignment; HS001 wrong state;
-- HQ001 quarantined; 23505 host or tenant already has a live assignment.

CREATE OR REPLACE FUNCTION cp_hostname_lock_tenant(p_tenant uuid) RETURNS void
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.tenant t WHERE t.id = p_tenant) THEN
        RAISE EXCEPTION 'hostname: no such tenant' USING ERRCODE = 'P0002';
    END IF;
    INSERT INTO public.tenant_branding_pointer (tenant_id) VALUES (p_tenant) ON CONFLICT (tenant_id) DO NOTHING;
    PERFORM 1 FROM public.tenant_branding_pointer p WHERE p.tenant_id = p_tenant FOR UPDATE;
END
$$;

-- A new, reassigned or reactivated assignment never inherits a published brand (docs/66 2a.10, 2b.2).
CREATE OR REPLACE FUNCTION cp_hostname_clear_published(p_tenant uuid) RETURNS void
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    UPDATE public.tenant_branding_pointer
       SET published_revision_id = NULL, published_revision_hash = NULL, published_assignment_id = NULL,
           published_by = NULL, published_at = NULL
     WHERE tenant_id = p_tenant
$$;

CREATE OR REPLACE FUNCTION cp_platform_hostname_assign(p_user uuid, p_session uuid, p_tenant uuid, p_host text, p_created_by text)
    RETURNS SETOF public.tenant_hostname_assignment
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    PERFORM public.cp_platform_check(p_user, p_session, interval '15 minutes');
    PERFORM set_config('lock_timeout', '5000', true);
    PERFORM public.cp_hostname_lock_tenant(p_tenant);
    PERFORM public.cp_hostname_clear_published(p_tenant);
    RETURN QUERY
        INSERT INTO public.tenant_hostname_assignment (host, tenant_id, state, created_by)
        VALUES (p_host, p_tenant, 'pending', p_created_by)
        RETURNING *;
END
$$;

CREATE OR REPLACE FUNCTION cp_platform_hostname_activate(p_user uuid, p_session uuid, p_id uuid)
    RETURNS SETOF public.tenant_hostname_assignment
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_tenant uuid;
BEGIN
    PERFORM public.cp_platform_check(p_user, p_session, interval '15 minutes');
    PERFORM set_config('lock_timeout', '5000', true);
    SELECT a.tenant_id INTO v_tenant FROM public.tenant_hostname_assignment a WHERE a.id = p_id;
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'hostname: no such assignment' USING ERRCODE = 'P0002';
    END IF;
    PERFORM public.cp_hostname_lock_tenant(v_tenant);
    -- Re-read under the locks: only a PENDING row activates, and it keeps its id (docs/66 2c.2).
    RETURN QUERY
        UPDATE public.tenant_hostname_assignment a
           SET state = 'active', activated_at = now()
         WHERE a.id = p_id AND a.state = 'pending'
        RETURNING a.*;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'hostname: assignment is not pending' USING ERRCODE = 'HS001';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION cp_platform_hostname_release(p_user uuid, p_session uuid, p_id uuid,
                                                         p_released_by text, p_quarantine_days integer)
    RETURNS SETOF public.tenant_hostname_assignment
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_tenant uuid;
    v_host   text;
BEGIN
    PERFORM public.cp_platform_check(p_user, p_session, interval '15 minutes');
    IF p_quarantine_days IS NULL OR p_quarantine_days < 30 THEN
        RAISE EXCEPTION 'hostname: quarantine is at least 30 days' USING ERRCODE = '22023';
    END IF;
    PERFORM set_config('lock_timeout', '5000', true);
    SELECT a.tenant_id, a.host INTO v_tenant, v_host FROM public.tenant_hostname_assignment a WHERE a.id = p_id;
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'hostname: no such assignment' USING ERRCODE = 'P0002';
    END IF;
    PERFORM public.cp_hostname_lock_tenant(v_tenant);
    PERFORM pg_advisory_xact_lock(hashtextextended('tenant_hostname:' || v_host, 0));
    RETURN QUERY
        UPDATE public.tenant_hostname_assignment a
           SET state = 'released', released_by = p_released_by,
               -- released_at is stamped by the trigger (clock_timestamp after the host lock). The default 30 days is
               -- left NULL so the trigger applies it from that same instant; a LONGER request is added to a clock
               -- read here, which is never later than the trigger's, and is always >= 720 h from it.
               quarantined_until = CASE WHEN p_quarantine_days = 30 THEN NULL
                                        ELSE clock_timestamp() + make_interval(hours => p_quarantine_days * 24) END
         WHERE a.id = p_id AND a.state IN ('pending', 'active')
        RETURNING a.*;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'hostname: assignment is already released' USING ERRCODE = 'HS001';
    END IF;
    PERFORM public.cp_hostname_clear_published(v_tenant);
END
$$;

-- Reactivation: a released assignment's host + tenant come back as a NEW assignment (new id), pending or, when
-- the operator knows the certificate is already in place, straight to active. Quarantine does not bar the
-- tenant that released it (the guard trigger only refuses OTHER tenants).
CREATE OR REPLACE FUNCTION cp_platform_hostname_reactivate(p_user uuid, p_session uuid, p_released_id uuid,
                                                            p_created_by text, p_activate boolean)
    RETURNS SETOF public.tenant_hostname_assignment
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_old public.tenant_hostname_assignment;
    v_new public.tenant_hostname_assignment;
BEGIN
    PERFORM public.cp_platform_check(p_user, p_session, interval '15 minutes');
    PERFORM set_config('lock_timeout', '5000', true);
    SELECT * INTO v_old FROM public.tenant_hostname_assignment a WHERE a.id = p_released_id;
    IF v_old.id IS NULL THEN
        RAISE EXCEPTION 'hostname: no such assignment' USING ERRCODE = 'P0002';
    END IF;
    PERFORM public.cp_hostname_lock_tenant(v_old.tenant_id);
    IF v_old.state <> 'released' THEN
        RAISE EXCEPTION 'hostname: assignment is not released' USING ERRCODE = 'HS001';
    END IF;
    PERFORM public.cp_hostname_clear_published(v_old.tenant_id);
    INSERT INTO public.tenant_hostname_assignment (host, tenant_id, state, created_by)
    VALUES (v_old.host, v_old.tenant_id, 'pending', p_created_by)
    RETURNING * INTO v_new;
    IF p_activate THEN
        UPDATE public.tenant_hostname_assignment a
           SET state = 'active', activated_at = now()
         WHERE a.id = v_new.id
        RETURNING * INTO v_new;
    END IF;
    RETURN NEXT v_new;
END
$$;

-- p_tenant NULL lists every assignment (the operator's overview); otherwise one tenant's history.
CREATE OR REPLACE FUNCTION cp_platform_hostname_list(p_user uuid, p_session uuid, p_tenant uuid)
    RETURNS SETOF public.tenant_hostname_assignment
    LANGUAGE plpgsql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    PERFORM public.cp_platform_check(p_user, p_session, interval '12 hours');
    RETURN QUERY
        SELECT a.* FROM public.tenant_hostname_assignment a
         WHERE p_tenant IS NULL OR a.tenant_id = p_tenant
         ORDER BY a.host, a.created_at, a.id;
END
$$;

-- Startup guard (docs/66 2.1): which of these (default / legacy) hosts is ALSO an active assignment? A
-- non-empty answer is a refusal to start. Returns only hosts the caller already named.
CREATE OR REPLACE FUNCTION cp_hostname_live_among(p_hosts text[])
    RETURNS SETOF text
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT DISTINCT a.host FROM public.tenant_hostname_assignment a
     WHERE a.host = ANY (p_hosts) AND a.state IN ('pending', 'active')
$$;

-- Startup safety (docs/66 runbook): how many ACTIVE assignments exist? With the host policy OFF the control plane
-- redeems unscoped, which would silently drop the scope of every active tenant host, so it refuses to start when
-- this is non-zero. Reveals only a count.
CREATE OR REPLACE FUNCTION cp_hostname_active_count()
    RETURNS bigint
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT count(*) FROM public.tenant_hostname_assignment a WHERE a.state = 'active'
$$;

-- ---------------------------------------------------------------------------------------------------
-- 4. Scoped redemption (docs/66 2a.1, 2b.4, 2b.5)
-- ---------------------------------------------------------------------------------------------------
-- p_unscoped is decided in Go from CONFIGURATION ONLY (the default host and the explicit legacy list). When it
-- is false the code must belong to the tenant that CURRENTLY holds p_host as an ACTIVE assignment; the check is
-- part of the same statement that takes the row lock, so release / reassignment / suspension serialize with the
-- redemption exactly like every other condition. No active assignment, a pending or released one, a foreign
-- tenant's code, an expired or spent code, a suspended tenant and a lock timeout ALL produce the same empty
-- result (the caller's generic invalid-code answer).
--
-- Bounded lock wait (2b.5): SKIP LOCKED is NOT used (it would turn a valid code into "invalid" whenever any
-- unrelated transaction held the row). The wait is capped at 50 ms; a timeout is the same generic rejection and
-- is documented as transient.
CREATE OR REPLACE FUNCTION cp_attended_redeem_scoped(p_code_hash bytea, p_pubkey bytea, p_name text,
                                                     p_device_id text, p_token_hash bytea, p_machine_expires timestamptz,
                                                     p_host text, p_unscoped boolean)
    RETURNS TABLE (session_id uuid, tenant_id uuid, group_id uuid, device_id text)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    s attended_session%ROWTYPE;
    v_prev_timeout text := current_setting('lock_timeout');
    v_host_tenant  uuid;
BEGIN
    BEGIN
        PERFORM set_config('lock_timeout', '50', true);
        -- LOCK ORDER: the ACTIVE ASSIGNMENT first (FOR SHARE, which conflicts with release's UPDATE), then the code
        -- row, both held until this transaction ends (through consumption). A release therefore either committed
        -- before we looked (we see state <> 'active' after re-evaluation of the locked row and refuse) or waits
        -- for this redemption to finish. It can never commit between our check and the consumption of the code.
        IF NOT p_unscoped THEN
            SELECT h.tenant_id INTO v_host_tenant FROM tenant_hostname_assignment h
                WHERE h.host = p_host AND h.state = 'active'
                FOR SHARE OF h;
            IF v_host_tenant IS NULL THEN
                PERFORM set_config('lock_timeout', v_prev_timeout, true);
                RETURN;
            END IF;
        END IF;
        SELECT * INTO s FROM attended_session a
            WHERE a.code_hash = p_code_hash AND a.state = 'pending' AND now() < a.expires_at
              AND EXISTS (
                  SELECT 1 FROM tenant t
                  WHERE t.id = a.tenant_id
                    AND t.disabled_at IS NULL
              )
              AND (p_unscoped OR a.tenant_id = v_host_tenant)
            FOR UPDATE OF a;
    EXCEPTION WHEN lock_not_available THEN
        RETURN;                       -- transient, and the same generic answer as any invalid code
    END;
    PERFORM set_config('lock_timeout', v_prev_timeout, true);
    IF s.id IS NULL THEN                -- (not FOUND: PERFORM above reset it)
        RETURN;                       -- caller maps empty -> ErrAttendedInvalid (generic)
    END IF;
    INSERT INTO machine (tenant_id, device_id, group_id, hostname, pubkey, ephemeral, expires_at)
        VALUES (s.tenant_id, p_device_id, s.group_id, p_name, p_pubkey, true, p_machine_expires);
    UPDATE attended_session
        SET state = 'redeemed', device_id = p_device_id, token_hash = p_token_hash, redeemed_at = now()
        WHERE id = s.id;
    RETURN QUERY SELECT s.id, s.tenant_id, s.group_id, p_device_id;
END $$;

-- The old six-argument entry point: UNSCOPED, so a rolled-back binary keeps today's behaviour. (Docs/66 2a.1
-- R2: a binary that does not scope must not be reachable on a tenant host.)
CREATE OR REPLACE FUNCTION cp_attended_redeem(p_code_hash bytea, p_pubkey bytea, p_name text,
                                              p_device_id text, p_token_hash bytea, p_machine_expires timestamptz)
    RETURNS TABLE (session_id uuid, tenant_id uuid, group_id uuid, device_id text)
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT * FROM public.cp_attended_redeem_scoped(p_code_hash, p_pubkey, p_name, p_device_id, p_token_hash,
                                                   p_machine_expires, '', true)
$$;

REVOKE ALL ON FUNCTION cp_hostname_lock_tenant(uuid)                                         FROM PUBLIC;
REVOKE ALL ON FUNCTION cp_hostname_clear_published(uuid)                                     FROM PUBLIC;
REVOKE ALL ON FUNCTION cp_platform_hostname_assign(uuid, uuid, uuid, text, text)             FROM PUBLIC;
REVOKE ALL ON FUNCTION cp_platform_hostname_activate(uuid, uuid, uuid)                       FROM PUBLIC;
REVOKE ALL ON FUNCTION cp_platform_hostname_release(uuid, uuid, uuid, text, integer)         FROM PUBLIC;
REVOKE ALL ON FUNCTION cp_platform_hostname_reactivate(uuid, uuid, uuid, text, boolean)      FROM PUBLIC;
REVOKE ALL ON FUNCTION cp_platform_hostname_list(uuid, uuid, uuid)                           FROM PUBLIC;
REVOKE ALL ON FUNCTION cp_hostname_live_among(text[])                                        FROM PUBLIC;
REVOKE ALL ON FUNCTION cp_hostname_active_count()                                          FROM PUBLIC;
REVOKE ALL ON FUNCTION cp_attended_redeem_scoped(bytea, bytea, text, text, bytea, timestamptz, text, boolean) FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        -- The two lock/clear helpers are called only from the functions above (definer context).
        REVOKE ALL ON FUNCTION cp_hostname_lock_tenant(uuid)     FROM rmt_app;
        REVOKE ALL ON FUNCTION cp_hostname_clear_published(uuid) FROM rmt_app;
        GRANT EXECUTE ON FUNCTION cp_platform_hostname_assign(uuid, uuid, uuid, text, text)        TO rmt_app;
        GRANT EXECUTE ON FUNCTION cp_platform_hostname_activate(uuid, uuid, uuid)                  TO rmt_app;
        GRANT EXECUTE ON FUNCTION cp_platform_hostname_release(uuid, uuid, uuid, text, integer)    TO rmt_app;
        GRANT EXECUTE ON FUNCTION cp_platform_hostname_reactivate(uuid, uuid, uuid, text, boolean) TO rmt_app;
        GRANT EXECUTE ON FUNCTION cp_platform_hostname_list(uuid, uuid, uuid)                      TO rmt_app;
        GRANT EXECUTE ON FUNCTION cp_hostname_live_among(text[])                                   TO rmt_app;
        GRANT EXECUTE ON FUNCTION cp_hostname_active_count()                                       TO rmt_app;
        GRANT EXECUTE ON FUNCTION cp_attended_redeem_scoped(bytea, bytea, text, text, bytea, timestamptz, text, boolean) TO rmt_app;
    END IF;
END
$$;
-- The wrapper keeps 0021's grant (PUBLIC), restated for a harness that applies this file without 0021 in the
-- same session. It is unscoped by definition, exactly as before.
GRANT EXECUTE ON FUNCTION cp_attended_redeem(bytea, bytea, text, text, bytea, timestamptz) TO PUBLIC;
