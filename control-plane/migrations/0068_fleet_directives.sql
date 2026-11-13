-- 0068: fleet agent directives (docs/65, server stages F0 + F1 + F2 + F3; review r1 contracts D-C1..D-C9).
--
-- Reinstall / remove an agent without opening a session. The control plane issues a SIGNED, per-device,
-- single-use directive (RMTDIRECTIVEv1, signed by a DEDICATED key - never the grant issuer) and relays it
-- through signaling to the authenticated device. This file adds:
--
--   * machine.status 'removed' (D-C9): the terminal tombstone. Registration AND enrollment refuse it.
--   * cp_machine_identity_by_device_id (F0 / D-C1): REDEFINED FROM ITS LATEST DEFINITION (0055: suspension,
--     pinned key, ephemeral expiry - every predicate kept) and now also returns the machine status so a
--     RETIRED machine can register in a RESTRICTED mode (directives only; the Go layer withholds the
--     restricted answer from a signaling that did not ask for it) while a REMOVED one is not resolvable.
--   * agent_directive: the directive ledger. One row per request, every reference tenant-qualified (a
--     plain FK bypasses RLS on write), at most ONE active directive per machine (partial unique index).
--   * tenant_directive_policy: the optional "require a second approver" policy and its version.
--   * machine_directive_guard trigger: retiring / un-retiring / moving a machine that has an active
--     directive is refused in the database (so no handler race can slip past), and a removed machine
--     never leaves 'removed'.
--   * cp_directive_sweep_candidates / cp_machine_key_removed: the two cross-tenant reads the background
--     sweeper and the PUBLIC enrollment path need (SECURITY DEFINER, exact-purpose, no writes).
--   * the 'remove_agent' capability on the Owner preset (role.capabilities is not read at runtime; kept in
--     sync like 0038).

-- --------------------------------------------------------------------------------------------------
-- machine.status gains the terminal 'removed'.
-- --------------------------------------------------------------------------------------------------
ALTER TABLE machine DROP CONSTRAINT IF EXISTS machine_status_check;
ALTER TABLE machine ADD CONSTRAINT machine_status_check
    CHECK (status IN ('active', 'quarantined', 'retired', 'removed'));

-- --------------------------------------------------------------------------------------------------
-- F0 / D-C1: the identity function, from its LATEST definition (0055) plus the status column and the
-- removed refusal. The return type changes, so it is dropped and recreated (and re-granted as 0010 did).
-- --------------------------------------------------------------------------------------------------
DROP FUNCTION IF EXISTS cp_machine_identity_by_device_id(text);
CREATE FUNCTION cp_machine_identity_by_device_id(p_device_id text)
    RETURNS TABLE (device_id text, tenant_id uuid, pubkey bytea, status text)
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT m.device_id, m.tenant_id, m.pubkey, m.status
    FROM public.machine m
    JOIN public.tenant t ON t.id = m.tenant_id
    WHERE m.device_id = p_device_id
      AND m.pubkey IS NOT NULL
      AND (NOT m.ephemeral OR m.expires_at IS NULL OR m.expires_at > now())
      AND t.disabled_at IS NULL
      AND m.status <> 'removed'
$$;
GRANT EXECUTE ON FUNCTION cp_machine_identity_by_device_id(text) TO PUBLIC;

-- --------------------------------------------------------------------------------------------------
-- tenant_directive_policy
-- --------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant_directive_policy (
    tenant_id               uuid        PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
    require_second_approver boolean     NOT NULL DEFAULT false,
    version                 bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at              timestamptz NOT NULL DEFAULT now()
);

-- --------------------------------------------------------------------------------------------------
-- agent_directive
-- --------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_directive (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          uuid        NOT NULL REFERENCES tenant(id),
    machine_id         uuid        NOT NULL,
    device_id          text        NOT NULL,        -- the machine's device id when requested (routing is from THIS row)
    key_fp             text        NOT NULL CHECK (key_fp ~ '^[0-9a-f]{64}$'), -- sha256(pubkey): the enrollment generation
    group_id           uuid        NOT NULL,        -- the machine's group when requested (informational)
    kind               text        NOT NULL CHECK (kind IN ('reinstall', 'uninstall')),
    state              text        NOT NULL CHECK (state IN
                           ('requested', 'issued', 'accepted', 'executing', 'reboot_pending', 'complete',
                            'failed', 'removal_unconfirmed', 'cancelled', 'expired')),
    requested_by       uuid        NOT NULL,
    requested_at       timestamptz NOT NULL,
    not_before         timestamptz NOT NULL,        -- end of the cancel window; nothing is issued earlier
    request_expires_at timestamptz NOT NULL,        -- a request not issued by now is expired
    require_approval   boolean     NOT NULL DEFAULT false,
    policy_version     bigint      NOT NULL DEFAULT 0,
    approved_by        uuid,
    approved_at        timestamptz,
    cancelled_by       uuid,
    cancelled_at       timestamptz,
    cancel_reason      text        CHECK (cancel_reason IS NULL OR length(cancel_reason) <= 300),
    issued_at          timestamptz,
    expires_at         timestamptz,
    nonce              bytea       CHECK (nonce IS NULL OR length(nonce) = 16),
    artifact           text,                         -- the signed RMTDIRECTIVEv1 JSON, set at issuance
    delivered_at       timestamptz,                  -- first relay to the authenticated device (signaling report)
    acked_at           timestamptz,                  -- last agent acknowledgement
    state_detail       text        NOT NULL DEFAULT '' CHECK (length(state_detail) <= 256),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    -- The credentials the requester / approver acted under (session id, credential epoch =
    -- user_credential.updated_at, mfa generation). Issuance compares them with the user's CURRENT state: a
    -- revoked session, a password change or an MFA reset since ends the directive.
    requested_session_id text      NOT NULL DEFAULT '',
    requested_cred_epoch timestamptz,
    requested_mfa_gen    bigint    NOT NULL DEFAULT 0,
    approved_session_id  text      NOT NULL DEFAULT '',
    approved_cred_epoch  timestamptz,
    approved_mfa_gen     bigint    NOT NULL DEFAULT 0,
    last_ack_ts_ms       bigint    NOT NULL DEFAULT 0, -- ts_ms of the last accepted ack: strictly increasing
    -- The last state the AGENT reported (for removal_unconfirmed: the state it was last known to be in), kept
    -- apart from the control plane's own outcome so a late genuine completion bound to it is still accepted.
    agent_state          text      NOT NULL DEFAULT '',

    FOREIGN KEY (tenant_id, machine_id)   REFERENCES machine       (tenant_id, id),
    FOREIGN KEY (tenant_id, group_id)     REFERENCES machine_group (tenant_id, id),
    FOREIGN KEY (tenant_id, requested_by) REFERENCES app_user      (tenant_id, id),
    FOREIGN KEY (tenant_id, approved_by)  REFERENCES app_user      (tenant_id, id),
    FOREIGN KEY (tenant_id, cancelled_by) REFERENCES app_user      (tenant_id, id),

    -- What each state requires, so no code path can leave a half-formed row.
    CONSTRAINT agent_directive_state_fields CHECK (
        (state = 'requested' AND issued_at IS NULL AND artifact IS NULL) OR
        (state IN ('issued', 'accepted', 'executing', 'reboot_pending', 'complete', 'removal_unconfirmed')
            AND issued_at IS NOT NULL AND expires_at IS NOT NULL AND artifact IS NOT NULL AND nonce IS NOT NULL) OR
        (state = 'cancelled' AND cancelled_at IS NOT NULL AND cancel_reason IS NOT NULL) OR
        (state IN ('failed', 'expired'))
    ),
    CONSTRAINT agent_directive_approval_fields CHECK (
        (approved_by IS NULL) = (approved_at IS NULL)
    )
);

-- At most ONE active directive per machine (D-C4). A second request is a unique violation the store maps.
-- 'removal_unconfirmed' stays active: a signed uninstall may still be executing, so the exclusion (and the
-- guard below) hold until it is resolved by a late agent report.
CREATE UNIQUE INDEX IF NOT EXISTS agent_directive_one_active
    ON agent_directive (machine_id)
    WHERE state IN ('requested', 'issued', 'accepted', 'executing', 'reboot_pending', 'removal_unconfirmed');

CREATE INDEX IF NOT EXISTS agent_directive_by_machine ON agent_directive (tenant_id, machine_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS agent_directive_by_tenant  ON agent_directive (tenant_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS agent_directive_open
    ON agent_directive (state, not_before) WHERE state IN ('requested', 'issued', 'accepted', 'executing', 'reboot_pending');

-- --------------------------------------------------------------------------------------------------
-- RLS and grants (mirror session_transfer). Directives are never deleted by the app role: central
-- evidence is kept (D-C9).
-- --------------------------------------------------------------------------------------------------
ALTER TABLE agent_directive ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_directive FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON agent_directive;
CREATE POLICY tenant_isolation ON agent_directive
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

ALTER TABLE tenant_directive_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_directive_policy FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_directive_policy;
CREATE POLICY tenant_isolation ON tenant_directive_policy
    USING      (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);

-- --------------------------------------------------------------------------------------------------
-- The machine guard (D-C4 / D-C9), enforced where no handler can race it. SECURITY INVOKER: it runs in the
-- caller's tenant context, and an UPDATE of a machine happens inside that tenant's transaction.
--   DR001  a machine with an ACTIVE directive may not change status or group (cancel the directive first)
--   DR002  a REMOVED machine never leaves 'removed'
-- The directive store takes the machine row FOR SHARE before it inserts a directive, so this guard and a
-- concurrent request serialize on the row lock: whichever commits first is seen by the other.
-- --------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION machine_directive_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    IF OLD.status = 'removed' AND NEW.status IS DISTINCT FROM OLD.status THEN
        RAISE EXCEPTION 'machine % is removed (terminal)', OLD.id USING ERRCODE = 'DR002';
    END IF;
    IF (NEW.status IS DISTINCT FROM OLD.status OR NEW.group_id IS DISTINCT FROM OLD.group_id)
       AND EXISTS (SELECT 1 FROM public.agent_directive d
                    WHERE d.machine_id = OLD.id
                      AND d.state IN ('requested', 'issued', 'accepted', 'executing', 'reboot_pending',
                                      'removal_unconfirmed'))
    THEN
        RAISE EXCEPTION 'machine % has an active directive; cancel it first', OLD.id USING ERRCODE = 'DR001';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS machine_directive_guard ON machine;
CREATE TRIGGER machine_directive_guard
    BEFORE UPDATE OF status, group_id ON machine
    FOR EACH ROW EXECUTE FUNCTION machine_directive_guard();

-- --------------------------------------------------------------------------------------------------
-- Cross-tenant reads (SECURITY DEFINER; apply as the RLS-bypassing owner role, search_path pinned).
-- --------------------------------------------------------------------------------------------------

-- D-C9: has this agent KEY been pinned on a machine that was REMOVED? The public enrollment path asks
-- before it pins a key, so a removed device's identity cannot silently come back as a new machine.
CREATE OR REPLACE FUNCTION cp_machine_key_removed(p_pubkey bytea) RETURNS boolean
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT EXISTS (SELECT 1 FROM public.machine m WHERE m.pubkey = p_pubkey AND m.status = 'removed')
$$;

-- The background sweeper's work list: what is due, across tenants, bounded. The sweeper then acts on each
-- item through the tenant-pinned store (re-checking everything under the tenant lock), so this only says
-- WHERE to look. 'unconfirmed' is for a directive that was executing and never reported a result.
--   * a request still awaiting its approval is NOT an 'issue' candidate (it would only bounce);
--   * actions are RANKED explicitly (expire, issue, unconfirmed, renotify) and, inside a rank, the OLDEST
--     due goes first, so a flood of renotifies can never crowd out an expiry or an issuance;
--   * 'renotify' is rate-limited: only a directive whose row has been quiet for a minute.
CREATE OR REPLACE FUNCTION cp_directive_sweep_candidates(p_now timestamptz, p_unconfirmed_after interval, p_limit integer)
    RETURNS TABLE (tenant_id uuid, directive_id uuid, action text)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT c.tenant_id, c.directive_id, c.action FROM (
        SELECT d.tenant_id, d.id AS directive_id,
               CASE
                   WHEN d.state = 'requested' AND p_now >= d.request_expires_at THEN 'expire'
                   WHEN d.state = 'requested' AND p_now >= d.not_before
                        AND NOT (d.require_approval AND d.approved_by IS NULL)  THEN 'issue'
                   WHEN d.state = 'issued'    AND p_now >= d.expires_at         THEN 'expire'
                   WHEN d.state IN ('accepted', 'executing', 'reboot_pending')
                        AND p_now >= d.updated_at + p_unconfirmed_after          THEN 'unconfirmed'
                   WHEN d.state = 'issued' AND d.delivered_at IS NULL
                        AND p_now >= d.updated_at + interval '1 minute'          THEN 'renotify'
               END AS action,
               CASE
                   WHEN d.state = 'requested' AND p_now >= d.request_expires_at THEN d.request_expires_at
                   WHEN d.state = 'requested' AND p_now >= d.not_before
                        AND NOT (d.require_approval AND d.approved_by IS NULL)  THEN d.not_before
                   WHEN d.state = 'issued'    AND p_now >= d.expires_at         THEN d.expires_at
                   WHEN d.state IN ('accepted', 'executing', 'reboot_pending')
                        AND p_now >= d.updated_at + p_unconfirmed_after          THEN d.updated_at + p_unconfirmed_after
                   ELSE d.updated_at
               END AS due_at
          FROM public.agent_directive d
         WHERE d.state IN ('requested', 'issued', 'accepted', 'executing', 'reboot_pending')
    ) c
    WHERE c.action IS NOT NULL
    ORDER BY CASE c.action WHEN 'expire' THEN 1 WHEN 'issue' THEN 2 WHEN 'unconfirmed' THEN 3 ELSE 4 END,
             c.due_at, c.directive_id
    LIMIT GREATEST(p_limit, 0)
$$;

REVOKE ALL ON FUNCTION cp_directive_sweep_candidates(timestamptz, interval, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION cp_machine_key_removed(bytea) FROM PUBLIC;

-- --------------------------------------------------------------------------------------------------
-- Grants. The sweep function is cross-tenant: the app role only.
-- --------------------------------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rmt_app') THEN
        GRANT SELECT, INSERT, UPDATE ON agent_directive          TO rmt_app;
        GRANT SELECT, INSERT, UPDATE ON tenant_directive_policy  TO rmt_app;
        -- 0005's default privileges hand rmt_app DELETE on every new table; central evidence is append-only (D-C9).
        REVOKE DELETE, TRUNCATE ON agent_directive, tenant_directive_policy FROM rmt_app;
        GRANT EXECUTE ON FUNCTION cp_directive_sweep_candidates(timestamptz, interval, integer) TO rmt_app;
        GRANT EXECUTE ON FUNCTION cp_machine_key_removed(bytea) TO rmt_app;
    END IF;
END
$$;

-- --------------------------------------------------------------------------------------------------
-- The Owner preset gains remove_agent (Admin and Technician never get it; it is not token-grantable).
-- --------------------------------------------------------------------------------------------------
UPDATE role
   SET capabilities = capabilities || ARRAY['remove_agent']
 WHERE tenant_id IS NULL
   AND key = 'owner'
   AND NOT ('remove_agent' = ANY(capabilities));

COMMENT ON TABLE agent_directive IS
    'One signed per-device directive (reinstall | uninstall), docs/65. requested (cancel window) -> issued -> '
    'accepted -> executing -> reboot_pending | complete | failed; removal_unconfirmed when a started removal '
    'never reported. A directive id is never a bearer credential: every transition re-derives authority.';
