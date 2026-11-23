-- 0073: "forget this machine" (docs/65 sec. 8): a control-plane-only terminal directive state.
--
-- An Owner may permanently forget a RETIRED machine whose removal will never be confirmed (the agent's final
-- acknowledgement never arrived: a reboot, the network, the machine was wiped) or that is simply gone. The
-- machine takes EXACTLY the D-C9 tombstone a confirmed removal applies (machine.status = 'removed', terminal),
-- and any directive still ACTIVE on it is closed in the SAME transaction. That closure needs a terminal state
-- that says what happened without claiming the agent confirmed anything: 'forgotten'. It is the control
-- plane's own conclusion, like 'removal_unconfirmed': an agent never reports it and never receives it (the
-- agent-reportable states are the closed list in crates/protocol/src/directive.rs and the control plane's
-- directiveTransitionAllowed; neither can name 'forgotten' as a source or a target).
--
-- This migration changes two constraints on agent_directive and nothing else:
--   * the state list gains 'forgotten';
--   * agent_directive_state_fields lets 'forgotten' carry whatever the row had (a directive closed while still
--     'requested' has no artifact; one closed while 'executing' has one), exactly like 'failed' and 'expired'.
-- Redefinition note: no function is redefined and none is added. The forget path runs the same machine UPDATE
-- the completed-removal path runs, so machine_directive_guard (0068: DR001 while a directive is active, DR002
-- once removed), cp_machine_identity_by_device_id (0068: refuses 'removed') and cp_machine_key_removed (0068:
-- the enrollment and attended-redeem tombstone) apply to a forgotten machine unchanged, and the app role needs
-- no new grant (it already updates agent_directive and machine under RLS).

ALTER TABLE agent_directive DROP CONSTRAINT IF EXISTS agent_directive_state_check;
ALTER TABLE agent_directive ADD CONSTRAINT agent_directive_state_check
    CHECK (state IN ('requested', 'issued', 'accepted', 'executing', 'reboot_pending', 'complete',
                     'failed', 'removal_unconfirmed', 'cancelled', 'expired', 'forgotten'));

ALTER TABLE agent_directive DROP CONSTRAINT IF EXISTS agent_directive_state_fields;
ALTER TABLE agent_directive ADD CONSTRAINT agent_directive_state_fields CHECK (
    (state = 'requested' AND issued_at IS NULL AND artifact IS NULL) OR
    (state IN ('issued', 'accepted', 'executing', 'reboot_pending', 'complete', 'removal_unconfirmed')
        AND issued_at IS NOT NULL AND expires_at IS NOT NULL AND artifact IS NOT NULL AND nonce IS NOT NULL) OR
    (state = 'cancelled' AND cancelled_at IS NOT NULL AND cancel_reason IS NOT NULL) OR
    (state IN ('failed', 'expired', 'forgotten'))
);

COMMENT ON TABLE agent_directive IS
    'One signed per-device directive (reinstall | uninstall), docs/65. requested (cancel window) -> issued -> '
    'accepted -> executing -> reboot_pending | complete | failed; removal_unconfirmed when a started removal '
    'never reported; forgotten when an owner forgot the machine (the control plane closed it, the agent never '
    'confirmed anything). A directive id is never a bearer credential: every transition re-derives authority.';
