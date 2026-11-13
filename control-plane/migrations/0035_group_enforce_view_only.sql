-- 0035_group_enforce_view_only.sql — per-group POLICY-ENFORCED view-only (docs/01 §5; the trust-model arc,
-- loops 79/80).
--
-- Loops 30-32 gave the product a view-only mode, but it is a SELF-SET toggle: the technician sends
-- SetViewOnly and can send it again to turn it back off, so nothing an ORGANISATION decided could bind a
-- session. Loop 79 built the missing mechanism (a control-plane-signed per-session access policy the AGENT
-- verifies and enforces as a one-way ratchet — see agent/src/session_policy.rs). This column is the ADMIN
-- CONTROL that drives it: when set, every session started on a machine in this group is minted a signed
-- view_only policy, and the technician cannot lift it.
--
-- It lives on group_session_policy rather than in a new table because it is the same kind of decision, about
-- the same subject, set by the same capability (CapManageGroups) on the same screen — and the composite FK
-- to machine_group(tenant_id, id) that makes a cross-tenant write impossible is already there.
--
-- NOTE FOR THE STORE: adding this column changes when a row may be DELETED. group_session_policy previously
-- deleted its row whenever the cap was set to 0 ("unlimited"), which was fine while the cap was the only
-- thing on it. With a second setting that rule would silently drop a group's view-only mandate whenever an
-- admin cleared its cap. The store now deletes only when the WHOLE policy is default
-- (GroupSessionPolicy.IsDefault: no cap AND not view-only).

ALTER TABLE group_session_policy
    ADD COLUMN enforce_view_only boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN group_session_policy.enforce_view_only IS
    'When true, every session on a machine in this group is admitted VIEW-ONLY and the agent enforces it '
    'via a control-plane-signed session policy the technician cannot decline (docs/01 §5).';
